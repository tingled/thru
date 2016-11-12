#!/usr/bin/env python
import argparse
import boto.ec2
import json
import logging
import os
import psutil
import requests

from subprocess import Popen, PIPE
from time import sleep


class Shepherd(object):
    def __init__(self, conf_file):
        self.conf_file = conf_file
        self.settings = self._load_conf()
        self.conn = self._load_conn()
        self.instance = self.get_instance()
        self.logger = logging.getLogger(__name__)

    def __getattr__(self, name):
        return self.settings.get(name)

    def _load_conf(self):
        return json.load(open(self.conf_file, 'r'))

    def _load_conn(self):
        return boto.ec2.connect_to_region(self.settings['region'])

    @staticmethod
    def local_ip():
        return requests.get('http://jsonip.com').json()['ip']

    def get_instance(self):
        reservations = self.conn.get_all_instances(
            filters={'tag:type': 'thru'}
        )
        assert len(reservations) == 1
        instances = reservations[0].instances
        assert len(instances) == 1
        return instances[0]

    def start_instance(self):
        while self.instance.state != 'running':
            if self.instance.state == 'stopped':
                self.logger.info('starting instance')
                self.instance.start()
            else:
                self.logger.info('instance state: {}. sleeping 5s'.format(
                    self.instance.state
                ))
                sleep(5)
                self.instance.update()

    def stop_instance(self):
        while self.instance.state != 'stopped':
            if self.instance.state == 'running':
                self.logger.info('stopping instance')
                self.instance.stop()
            else:
                self.logger.info('instance state: {}. sleeping 5s'.format(
                    self.instance.state
                ))
                sleep(5)
                self.instance.update()

    def _instance_security_group(self):
        return self.conn.get_all_security_groups(
            group_ids=[self.instance.groups[0].id]
        )[0]

    def swap_rules(self):
        sg = self._instance_security_group()
        cur_ip = Shepherd.local_ip().split('.')
        cur_ip[-1] = "0"
        cur_ip = '.'.join(cur_ip) + '/24'

        for rule in sg.rules:
            if rule.grants != [cur_ip]:
                self.logger.info("revoking rule")
                for grant in rule.grants:
                    assert sg.revoke(
                        ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=grant
                    )

        self.logger.info("creating new rule")
        assert sg.authorize(
            ip_protocol='tcp',
            to_port=self.remote_port,
            from_port=self.remote_port,
            cidr_ip=cur_ip
        )

        # add ssh rule
        assert sg.authorize(
            ip_protocol='tcp',
            to_port=22,
            from_port=22,
            cidr_ip=cur_ip
        )

    def _ssh_login_str(self):
        return '{}@{}'.format(self.remote_user, self.instance.ip_address)

    def dig_tunnel(self):
        port_str = '{}:{}:{}'.format(self.local_port, self.local_host, self.remote_port)
        cred_str = self._ssh_login_str()
        cmd = [
            'ssh', '-o', 'StrictHostKeyChecking=no', '-L', port_str, '-N',
            '-i', self.pem_file, cred_str
        ]
        self.logger.info('opening ssh tunnel')
        self.logger.info(cmd)
        Popen(cmd, preexec_fn=os.setpgrp)

    def kill_tunnel(self):
        cred_str = self._ssh_login_str()
        for p in psutil.process_iter():
            if p.name() == 'ssh' and p.cmdline()[-1] == cred_str:
                self.logger.info('killing ssh proc with pid={}'.format(p.pid))
                p.terminate()

    @staticmethod
    def _proxy_cmd(desired_state, secure):
        set_str = '-set{}webproxystate'.format('secure' if secure else '')
        return ['networksetup', set_str, 'Wi-Fi', desired_state]

    def set_proxy(self, state):
        assert state in ['off', 'on']
        self.logger.info("turning network proxy {}".format(state))
        for cmd in [Shepherd._proxy_cmd(state, secure=s) for s in [True, False]]:
            self.logger.info(cmd)
            proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate()


def init_logging(args):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.WARNING)
    log_format = "%(asctime)s -  %(message)s"
    formatter = logging.Formatter(log_format)
    level = logging.INFO

    if args.log_file:
        handler = logging.FileHandler(args.log_file)
    else:
        handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(formatter)

    logger.addHandler(handler)


def start_main(args):
    shep = Shepherd(args.settings)
    shep.start_instance()
    shep.dig_tunnel()
    shep.set_proxy('on')


def stop_main(args):
    shep = Shepherd(args.settings)
    shep.set_proxy('off')
    shep.kill_tunnel()


def restart_main(args):
    stop_main(args)
    shep = Shepherd(args.settings)
    shep.swap_rules()
    start_main(args)
    # TODO reset security groups, reset tunnel


def terminate_main(args):
    # TODO stop instance
    stop_main(args)
    shep = Shepherd(args.settings)
    shep.stop_instance()


def parse_args():
    parser = argparse.ArgumentParser(prog='launch')

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        '-s', '--settings', default='settings.json',
        help='Settings file which contains sensitive information'
    )
    parent_parser.add_argument('-l', '--log-file', help='output log file')

    sp = parser.add_subparsers(title='commands')
    start = sp.add_parser(
        'start', help='start the tunnel', parents=[parent_parser]
    )
    start.set_defaults(func=start_main)

    stop = sp.add_parser('stop', help='stop the tunnel', parents=[parent_parser])
    stop.set_defaults(func=stop_main)

    terminate = sp.add_parser(
        'terminate', help='terminate running instance and stop the tunnel',
        parents=[parent_parser]
    )
    terminate.set_defaults(func=terminate_main)

    restart = sp.add_parser(
        'restart', parents=[parent_parser],
        help='restart the tunnel and update proxy'
    )
    restart.set_defaults(func=restart_main)

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    init_logging(args)
    args.func(args)

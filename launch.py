import boto.ec2
import json
import requests


class Shepherd(object):
    def __init__(self, conf_file='settings.json'):
        self.conf_file = conf_file
        self.settings = self._load_conf()
        self.conn = self._load_conn()
        self.instance = self.get_instance()

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

    def _instance_security_group(self, instance):
        return self.conn.get_all_security_groups(
            group_ids=[instance.groups[0].id]
        )[0]

    def swap_rules(self, instance):
        sg = self._instance_security_group(instance)
        cur_ip = Shepherd.local_ip().split('.')
        cur_ip[-1] = "0"
        cur_ip = '.'.join(cur_ip) + '/24'

        for rule in sg.rules:
            if rule.grants != [cur_ip]:
                for grant in rule.grants:
                    assert sg.revoke(
                        ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=grant
                    )

        assert sg.authorize(
            ip_protocol='tcp',
            to_port=self.settings['port'],
            from_port=self.settings['port'],
            cidr_ip=cur_ip
        )

        # add ssh rule
        assert sg.authorize(
            ip_protocol='tcp',
            to_port=22,
            from_port=22,
            cidr_ip=cur_ip
        )

    def dig_tunnel(self):
        pass


shep = Shepherd()
shep.swap_rules(shep.instance)

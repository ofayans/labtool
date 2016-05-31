#!/usr/bin/env python
from argparse import ArgumentParser
import os
from ovirtsdk.infrastructure.errors import RequestError
from threading import Thread
from backend import RHEVM
import locals

parser = ArgumentParser()
parser.add_argument('--action', '-a', dest='action', type=str,
                    default='create', help='Possible values are: create, start, \
                    stop, delete, all, inventory')
parser.add_argument('--prefix', '-p', dest='prefix', type=str,
                    help='Prefix, that all VM names will have')
parser.add_argument('--suffix', '-s', dest='suffix', type=str,
                    help='Suffix, that all VM names will have')
parser.add_argument('--template-name', '-t', dest='template', type=str,
                    help='Template name')

parser.add_argument('--lab', '-l', type=str, dest='lab', default='abcd',
                    help='RHEVM lab to connect to. Possible values are: \
                    abcd, brno')
parser.add_argument('--num_vms', '-n', type=int,
                    dest='num_vms', help='Number of VMs to process')

options = parser.parse_args()


def load_vms(vm_list):
    result = []
    for vm in vm_list:
        result.append(api.load_vm(vm.name, vm, interactive=False))
    return result


def get_vm_list(prefix, suffix, count):
    result = []
    for i in range(1, count + 1):
        vm_name = "%s%s%i" % (prefix, suffix, i)
        vm = api.get_vm(vm_name)
        result.append(vm)
    return result


def create_vms(prefix, suffix, template_name, count):
    vm_list = []
    for i in range(1, count + 1):
        vm_name = "%s%s%i" % (prefix, suffix, i)
        print "Creating %s from template %s" % (vm_name, template_name)
        try:
            vm = api.create_vm(vm_name, memory=locals.MEMORY,
                               template=template_name)
        except RequestError:
            try:
                vm = api.get_vm(vm_name)
            except:
                continue
        vm_list.append(vm)
    return vm_list


def start_vms(hosts):
    hosts_done = []
    for host in hosts:
        hosts_done.append(api.start(host.name, host))
    return hosts_done


def delete_vms(hosts):
    for host in hosts:
        thread = Thread(target=api.remove_vm(host.name))
        thread.start()


def stop_vms(hosts):
    for host in hosts:
        host.stop()


def prepare_inventory(hostlist, inventory_file, config_file, testrc_file):
    result = []
    for host in hostlist:
        result.append({'fqdn': host.fqdn, 'ip': host.ip})
    with open(inventory_file, 'w') as invfile:
        hostnames = []
        for host in result:
            if host['fqdn'] != '.':
                hostnames.append(host['fqdn'][:-1])
        restext = '\n'.join(hostnames)
        invfile.write(restext)

    domainname = result[0]['fqdn'][:-1].replace('vm', 'dom')
    ipadomain = ipadomainskel % domainname
    cleanresult = []
    for host in result:
        if host['fqdn'] and host['ip']:
            cleanresult.append(host)
    hosts = masterskel % (cleanresult[0]['fqdn'],
                          cleanresult[0]['fqdn'][:-1],
                          cleanresult[0]['ip'])
    testrc_hosts = [cleanresult[0]['fqdn'][:-1]]
    for host in cleanresult[1:]:
        hosts += replicaskel % (host['fqdn'],
                                host['fqdn'][:-1],
                                host['ip'])
        testrc_hosts.append(host['fqdn'][:-1])

    with open(config_file, 'w') as configfile:
        resulttext = header + ipadomain + hosts
        configfile.write(resulttext)
    with open(testrc_file, 'w') as testrcfile:
        testrcfile.write(testrcskel % (testrc_hosts[0],
                                       " ".join(testrc_hosts[1:]),
                                       config_file))


if __name__ == '__main__':
    prefix = options.prefix or os.environ['USER']
    num_replicas = options.num_vms or locals.NUM_VMS
    vm_suffix = options.suffix or locals.VM_SUFFIX
    locals.set_locale(options.lab)

    header = "admin_name: admin\n\
admin_password: %s\n\
debug: true\n\
dirman_dn: cn=Directory Manager\n\
dirman_password: %s\n\
dns_forwarder: %s\n\
domain_level: 1\n\
root_ssh_key_filename: %s\n\
test_dir: %s\n\
domains:\n" % (locals.ADMIN_PASSWORD,
               locals.DIRMAN_PASSWORD,
               locals.DNS_FORWARDER,
               locals.PRIVATE_KEY,
               locals.TEST_DIR)

    ipadomainskel = "- name: %s\n\
  type: IPA\n\
  hosts:\n"

    masterskel = "  - name: %s\n\
    external_hostname: %s\n\
    ip: %s\n\
    role: master\n"

    replicaskel = "  - name: %s\n\
    external_hostname: %s\n\
    ip: %s\n\
    role: replica\n"

    testrcskel = "export MASTER=%s\n\
export REPLICA='%s'\n\
export IPATEST_YAML_CONFIG=%s"

    if options.lab == 'brno':
        raise NotImplementedError('Brno lab is not tested, most probabaly the\
                                   script would not work. ')
    api = RHEVM(url=locals.URL, cluster_name=locals.CLUSTER_NAME,
                ca_file=locals.CA_FILE, username=locals.USERNAME,
                password=locals.PASSWORD, kerberos=locals.KERBEROS)
    template_name = options.template or locals.TEMPLATE_NAME

    if options.action == 'create':
        create_vms(prefix, vm_suffix, template_name, count=num_replicas)
    elif options.action == 'start':
        vm_list = get_vm_list(prefix, vm_suffix, num_replicas)
        start_vms(vm_list)
    elif options.action == 'all':
        vm_list = create_vms(prefix, vm_suffix,
                             template_name, count=num_replicas)
        vm_list_started = start_vms(vm_list)
        # A workaround for current ABCDE lab issue when a freshly started VM
        # does not display FQDN untill it is once more restarted
        stop_vms(vm_list_started)
        start_vms(vm_list)
        # End of workaround
        host_list = load_vms(vm_list_started)
        prepare_inventory(host_list, locals.INVENTORY_FILE,
                          locals.CONFIG_FILE, locals.TESTRC_FILE)
    elif options.action == 'stop':
        vm_list = get_vm_list(prefix, vm_suffix, num_replicas)
        stop_vms(vm_list)
    elif options.action == 'delete':
        vm_list = get_vm_list(prefix, vm_suffix, num_replicas)
        delete_vms(vm_list)
    elif options.action == 'inventory':
        vm_list = get_vm_list(prefix, vm_suffix, num_replicas)
        host_list = load_vms(vm_list)
        prepare_inventory(host_list, locals.INVENTORY_FILE,
                          locals.CONFIG_FILE, locals.TESTRC_FILE)

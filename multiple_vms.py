#!/usr/bin/env python
from argparse import ArgumentParser
import os
from ovirtsdk.infrastructure.errors import RequestError
from threading import Thread
from backend import RHEVM
import locals

parser = ArgumentParser()
parser.add_argument('--action', '-a', dest='action', type=str,
                    default='create', help="""Possible values are: create,
 start, stop, delete, all, inventory, snapshot, revert, delete_invalid,
 restart_invalid""")
parser.add_argument('--prefix', '-p', dest='prefix', type=str,
                    help='Prefix, that all VM names will have')
parser.add_argument('--suffix', '-s', dest='suffix', type=str,
                    help='Suffix, that all VM names will have')
parser.add_argument('--template-name', '-t', dest='template', type=str,
                    help='Template name')

parser.add_argument('--lab', '-l', type=str, dest='lab', default='abcd',
                    help="RHEVM lab to connect to. Possible values are: \
                    %s" % (", ".join(locals.POSSIBLE_LABS)))
parser.add_argument('--num-vms', '-n', type=int,
                    dest='num_vms', help='Number of VMs to process')
parser.add_argument('--initial-vm-num', '-i', type=int,
                    dest='initial_vm_num', help='Number of the first vm to be \
                    processed')

options = parser.parse_args()


def load_vms(vm_list):
    result = []
    for vm in vm_list:
        try:
            result.append(api.load_vm(vm.name, vm, start=False, interactive=False, update=False))
        except RequestError:
             # If rhevm does not respond - to hell with it!
            pass
    return result


def get_vm_list(prefix, suffix, array):
    result = []
    for i in array:
        vm_name = "%s%s%i" % (prefix, suffix, i)
        try:
            vm = api.get_vm(vm_name)
            result.append(vm)
        except ValueError:
        # The machine was manually deleted
            continue
    return result


def create_vms(prefix, suffix, template_name, array):
    vm_list = []
    for i in array:
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


def make_snapshots(hosts):
    for host in hosts:
        api.make_snapshot(host.name)


def revert_to_snapshots(hosts):
    for host in hosts:
        try:
            api.revert_to_snapshot(host.name)
        except Exception:
            pass


def start_vms(hosts):
    hosts_done = []
    for host in hosts:
        try:
            host = api.start(host.name, host)
        except ValueError:
            pass  # Sometimes RHEVM sucs really hard
        hosts_done.append(host)
    return hosts_done


def delete_vms(hosts):
    for host in hosts:
        thread = Thread(target=api.remove_vm(host.name))
        thread.start()


def stop_vms(hosts):
    for host in hosts:
        host.stop()


def restart_invalid_hosts(hosts):
    """Restarts those of the provided hosts that do not have
    fqdn or ip exported"""
    for host in hosts:
        if not (host.fqdn and host.ip):
            api.stop(host.name)
            api.start(host.name, wait=False)


def delete_invalid_hosts(hosts):
    """Deletes those of the provided hosts that do not have
    fqdn or ip exported"""
    for host in hosts:
        if not (host.fqdn and host.ip):
            api.remove_vm(host.name)

def prepare_inventory(hostlist, inventory_file, config_file, testrc_file):
    result = []
    for host in hostlist:
        if host.hostname and host.ip:
            result.append({'fqdn': host.fqdn, 'ip': host.ip})
    with open(inventory_file, 'w') as invfile:
        hostnames = []
        for host in result:
            if host['fqdn'] != '.':
                hostnames.append(host['fqdn'][:-1])
        restext = '\n'.join(hostnames)
        invfile.write(restext)

    domainname = result[0]['fqdn'][:-1].replace('vm', 'dom')
    ipadomain = locals.IPADOMAINSKEL % domainname
    hosts = locals.MASTERSKEL % (result[0]['fqdn'],
                                 result[0]['fqdn'][:-1],
                                 result[0]['ip'])
    testrc_hosts = [result[0]['fqdn'][:-1]]
    for host in result[1:]:
        hosts += locals.REPLICASKEL % (host['fqdn'],
                                       host['fqdn'][:-1],
                                       host['ip'])
        testrc_hosts.append(host['fqdn'][:-1])

    with open(config_file, 'w') as configfile:
        resulttext = locals.CONFIG_HEADER + ipadomain + hosts
        configfile.write(resulttext)
    with open(testrc_file, 'w') as testrcfile:
        testrcfile.write(locals.TESTRCSKEL % (testrc_hosts[0],
                                              " ".join(testrc_hosts[1:]),
                                              config_file))


if __name__ == '__main__':
    prefix = options.prefix or os.environ['USER']
    num_replicas = options.num_vms or locals.NUM_VMS
    if options.initial_vm_num:
        vm_array = range(options.initial_vm_num, num_replicas + 1)
    else:
        vm_array = range(num_replicas + 1)[1:]
    vm_suffix = options.suffix or locals.VM_SUFFIX
    locals.set_locale(options.lab)

    api = RHEVM(url=locals.URL, cluster_name=locals.CLUSTER_NAME,
                ca_file=locals.CA_FILE, username=locals.USERNAME,
                password=locals.PASSWORD, kerberos=locals.KERBEROS)
    template_name = options.template or locals.TEMPLATE_NAME

    if options.action == 'create':
        create_vms(prefix, vm_suffix, template_name, vm_array)
    elif options.action == 'start':
        vm_list = get_vm_list(prefix, vm_suffix, vm_array)
        start_vms(vm_list)
    elif options.action == 'snapshot':
        vm_list = get_vm_list(prefix, vm_suffix, vm_array)
        make_snapshots(vm_list)
    elif options.action == 'revert':
        vm_list = get_vm_list(prefix, vm_suffix, vm_array)
        revert_to_snapshots(vm_list)
    elif options.action == 'all':
        vm_list = create_vms(prefix, vm_suffix,
                             template_name, vm_array)
        vm_list_started = start_vms(vm_list)
        host_list = load_vms(vm_list_started)
        prepare_inventory(host_list, locals.INVENTORY_FILE,
                          locals.CONFIG_FILE, locals.TESTRC_FILE)
    elif options.action == 'stop':
        vm_list = get_vm_list(prefix, vm_suffix, vm_array)
        stop_vms(vm_list)
    elif options.action == 'delete':
        vm_list = get_vm_list(prefix, vm_suffix, vm_array)
        delete_vms(vm_list)
    elif options.action == 'inventory':
        vm_list = get_vm_list(prefix, vm_suffix, vm_array)
        host_list = load_vms(vm_list)
        prepare_inventory(host_list, locals.INVENTORY_FILE,
                          locals.CONFIG_FILE, locals.TESTRC_FILE)
    elif options.action == 'delete_invalid':
        vm_list = get_vm_list(prefix, vm_suffix, vm_array)
        hosts = load_vms(vm_list)
        delete_invalid_hosts(hosts)
    elif options.action == 'restart_invalid':
        vm_list = get_vm_list(prefix, vm_suffix, vm_array)
        hosts = load_vms(vm_list)
        restart_invalid_hosts(hosts)

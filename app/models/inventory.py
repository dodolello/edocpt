from dataclasses import dataclass
from typing import List
from pyVmomi import vim


def collect_objects(content, vimtype):
    container = content.viewManager.CreateContainerView(content.rootFolder, [vimtype], True)
    return container.view


@dataclass
class VMInfo:
    name: str
    power_state: str
    mo_ref: vim.VirtualMachine


@dataclass
class HostInfo:
    name: str
    mo_ref: vim.HostSystem


def fetch_inventory(si):
    content = si.RetrieveContent()
    vms = [VMInfo(vm.name, vm.runtime.powerState, vm) for vm in collect_objects(content, vim.VirtualMachine)]
    hosts = [HostInfo(host.name, host) for host in collect_objects(content, vim.HostSystem)]
    return vms, hosts


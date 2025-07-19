import os
import ssl
from dataclasses import dataclass
from typing import Optional
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim


@dataclass
class VCProfile:
    host: str
    username: str
    password: str
    port: int = 443
    name: str = "default"


class VSphereConnection:
    def __init__(self, profile: VCProfile):
        self.profile = profile
        self.si = None

    def connect(self) -> bool:
        if self.si:
            return True
        context = ssl._create_unverified_context()
        try:
            self.si = SmartConnect(
                host=self.profile.host,
                user=self.profile.username,
                pwd=self.profile.password,
                port=self.profile.port,
                sslContext=context,
            )
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False

    def disconnect(self):
        if self.si:
            Disconnect(self.si)
            self.si = None

    def is_connected(self) -> bool:
        return self.si is not None

    def get_root_folder(self) -> Optional[vim.Folder]:
        if self.si:
            return self.si.content.rootFolder
        return None

import sys
from PyQt6 import QtWidgets, QtGui
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTreeView,
    QSplitter,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from services.connection import VCProfile, VSphereConnection
from models.inventory import fetch_inventory


class ConnectThread(QThread):
    connected = pyqtSignal(bool, str)

    def __init__(self, profile: VCProfile):
        super().__init__()
        self.profile = profile
        self.conn = VSphereConnection(profile)

    def run(self):
        success = self.conn.connect()
        self.connected.emit(success, self.profile.host)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("vSphere GUI Automation Tool")
        self.resize(800, 600)
        self.conn = None
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        layout = QVBoxLayout(central)
        form = QHBoxLayout()

        self.host_edit = QLineEdit()
        self.user_edit = QLineEdit()
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addWidget(QLabel("Host"))
        form.addWidget(self.host_edit)
        form.addWidget(QLabel("User"))
        form.addWidget(self.user_edit)
        form.addWidget(QLabel("Password"))
        form.addWidget(self.pass_edit)
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self._on_connect)
        form.addWidget(self.connect_btn)

        layout.addLayout(form)

        self.tree = QTreeView()
        layout.addWidget(self.tree)

        self.status = QLabel("Disconnected")
        layout.addWidget(self.status)

        self.setCentralWidget(central)

    def _on_connect(self):
        profile = VCProfile(
            host=self.host_edit.text(),
            username=self.user_edit.text(),
            password=self.pass_edit.text(),
        )
        self.thread = ConnectThread(profile)
        self.thread.connected.connect(self._on_connected)
        self.thread.start()
        self.status.setText("Connecting...")

    def _on_connected(self, success: bool, host: str):
        if success:
            self.status.setText(f"Connected to {host}")
            self.conn = self.thread.conn
            self.load_inventory()
        else:
            self.status.setText("Connection failed")

    def load_inventory(self):
        if not self.conn:
            return
        vms, hosts = fetch_inventory(self.conn.si)
        model = QtGui.QStandardItemModel()
        root = model.invisibleRootItem()
        host_item = QtGui.QStandardItem("Hosts")
        for h in hosts:
            host_item.appendRow(QtGui.QStandardItem(h.name))
        vm_item = QtGui.QStandardItem("Virtual Machines")
        for v in vms:
            vm_item.appendRow(QtGui.QStandardItem(f"{v.name} ({v.power_state})"))
        root.appendRow(host_item)
        root.appendRow(vm_item)
        model.setHorizontalHeaderLabels(["Inventory"])
        self.tree.setModel(model)
        self.tree.expandAll()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

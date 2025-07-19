# vSphere GUI Automation Tool

This project provides a Python 3 application built with **PyQt6** and **PyVmomi** for interacting with VMware vSphere environments. The tool aims to support bulk VM operations, reporting, and a wide variety of administrative tasks via a desktop GUI.

The current codebase includes a small framework:

- `services/connection.py` – connection handling for vCenter profiles.
- `models/inventory.py` – helpers for retrieving inventory objects.
- `main.py` – basic PyQt application demonstrating connection and inventory tree.

The implementation follows the roadmap outlined in the specification and can be extended with additional features such as scheduling, metrics dashboards, and backup integrations.

Run the application with:

```bash
python3 -m app.main
```

Dependencies are installed via pip:

```bash
pip install pyvmomi PyQt6
```

This repository is in an early proof‑of‑concept stage and does not yet include all functions described in the full specification.

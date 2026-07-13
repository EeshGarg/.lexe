# `.lexe` — Linux Executable Application Format

## Project Purpose

The Linux desktop has advanced enormously, but installing desktop applications is still fragmented.

A user may need to:

* search a distribution repository;
* add a third-party repository;
* download an AppImage;
* configure Flatpak;
* extract an archive;
* run an installation script;
* manually create a desktop shortcut;
* install Wine or another compatibility layer;
* determine how the application should update.

Windows generally offers a simpler mental model:

> Download the program, double-click it, and follow the installer.

macOS provides another useful model:

> Applications are self-contained bundles that can be opened and managed consistently.

Linux provides decentralization, transparency, portability, and user control, but lacks one universal double-click application experience.

The `.lexe` format is intended to combine:

* the double-click simplicity of Windows;
* the application-bundle cleanliness of macOS;
* the decentralization and technical flexibility of Linux.

---

# Core Principle

A `.lexe` file is a self-describing application package or application launcher.

The user should be able to:

1. Download a `.lexe` file.
2. Double-click it.
3. Review the application, publisher, permissions, source, and installation location.
4. Press Install.
5. Launch the installed application normally.
6. Receive updates from an approved source.
7. Uninstall it completely.

The user should not need to understand package managers, repositories, Wine prefixes, desktop entries, environment variables, dependency installation, or application update mechanisms.

---

# Lexe Components

## 1. Lexe Runtime

The Lexe Runtime is the trusted system component that handles `.lexe` files.

It is responsible for:

* opening `.lexe` packages;
* parsing the application manifest;
* verifying signatures and hashes;
* displaying installation information;
* resolving application dependencies;
* selecting the proper execution runtime;
* installing applications in userspace;
* requesting privilege escalation only when genuinely necessary;
* creating launchers and file associations;
* checking for updates;
* repairing installations;
* uninstalling applications;
* maintaining a local application registry.

The runtime should be open source and auditable.

The runtime itself should be available through normal distribution repositories, Flatpak, or an official bootstrap installer.

### Reference Implementation

The reference Lexe Runtime is implemented in modern C++.

The `.lexe` specification itself is language-neutral, and compatible third-party runtimes may be implemented in any language.

---

## 2. `.lexe` Package

A `.lexe` package may operate in one of three modes.

### Bundled Package

The complete application is contained inside the `.lexe` file.

This is appropriate for:

* offline installation;
* small applications;
* portable applications;
* archival releases;
* applications distributed directly by their developers.

### Network Package

The `.lexe` file contains a signed manifest and retrieves the application payload from one or more approved sources.

This is appropriate for:

* large applications;
* frequently updated applications;
* commercial software;
* applications with multiple architecture-specific builds.

### Launcher Package

The `.lexe` file describes how to install or launch an application supplied by another system.

Examples include:

* installing a package from a distro repository;
* installing a Flatpak;
* installing an AppImage;
* launching a Windows program through Wine;
* launching an x86 application through Box64;
* installing from a private corporate repository;
* launching an application stored on removable media.

---

# Standard User Flow

## Installation

1. The user double-clicks a `.lexe` file.
2. The Lexe Runtime opens the package.
3. The runtime verifies:

   * package structure;
   * manifest validity;
   * payload hashes;
   * publisher signature;
   * update-source ownership;
   * architecture compatibility.
4. The runtime displays:

   * application name;
   * publisher;
   * version;
   * application type;
   * installation source;
   * requested permissions;
   * disk usage;
   * update policy;
   * whether compatibility tools such as Wine will be used.
5. The user selects an installation configuration.
6. The application is installed in userspace by default.
7. Privilege escalation is requested through Linux policy mechanisms only when required.
8. A desktop entry, application-menu entry, icons, and optional file associations are created.
9. The application becomes available like any other installed desktop application.

---

# Installation Sources

A `.lexe` application may be installed from:

* a payload embedded in the `.lexe` file;
* the application developer’s repository;
* GitHub, GitLab, Codeberg, or another forge;
* a Linux distribution repository;
* Flathub or another Flatpak repository;
* a private company repository;
* a local network repository;
* removable storage;
* a user-selected mirror;
* a previously downloaded cache.

The package publisher may provide recommended sources, but the user can choose another trusted source when compatible builds are available.

The user’s chosen source becomes the default update source unless explicitly changed later.

---

# Execution Backends

The `.lexe` format should support multiple application types rather than inventing a new binary ABI.

## Native Linux

Supported native payloads may include:

* ELF executables;
* application directories;
* AppImages;
* tar archives;
* distribution packages;
* Flatpak references or bundles;
* OCI-based application images;
* scripts with declared interpreters.

## Windows Compatibility

Windows applications may be launched using:

* Wine;
* Proton;
* Bottles-compatible environments;
* application-specific Wine prefixes.

The manifest can declare:

* required Wine version;
* Windows architecture;
* required DLL overrides;
* prefix configuration;
* launch executable;
* environment variables;
* optional runtime components.

## Cross-Architecture Compatibility

Where supported, Lexe may configure:

* Box64;
* Box86;
* FEX;
* QEMU user-mode emulation;
* Rosetta-compatible alternatives where legally and technically available.

The runtime must tell the user when emulation is being used and warn when performance or compatibility may be reduced.

## Web and Hybrid Applications

Lexe may also support:

* Progressive Web Applications;
* Electron applications;
* Tauri applications;
* local web applications;
* WebAssembly applications.

---

# Userspace-First Installation

Applications should be installed without administrative privileges whenever possible.

Suggested default directories:

```text
~/.local/share/lexe/apps/
~/.local/share/lexe/data/
~/.local/share/lexe/runtimes/
~/.local/share/lexe/icons/
~/.local/share/applications/
~/.cache/lexe/
~/.config/lexe/
```

A typical installed application could use:

```text
~/.local/share/lexe/apps/com.example.application/
├── current/
├── versions/
│   ├── 1.0.0/
│   └── 1.1.0/
├── manifest.json
├── installation.json
├── update.json
└── launcher
```

System-wide installation should be optional rather than the default.

---

# Privilege Escalation

Lexe should not reproduce Windows UAC directly.

On Linux, privilege escalation should use existing security systems such as:

* polkit;
* desktop authentication agents;
* narrowly scoped privileged helper services.

The runtime must never blindly execute an arbitrary package script as root.

When elevation is required, the interface should explain exactly why.

Examples:

* installing a system driver;
* adding a system service;
* creating a system-wide file association;
* installing a shared runtime;
* modifying a protected device rule.

The privileged helper should expose a small, predefined set of operations rather than accepting unrestricted shell commands.

---

# Application Manifest

Every `.lexe` package contains a machine-readable manifest.

Example:

```json
{
  "lexeVersion": "0.1",
  "id": "com.example.application",
  "name": "Example Application",
  "version": "1.4.2",
  "publisher": {
    "name": "Example Corporation",
    "website": "https://example.com",
    "publicKey": "ed25519:..."
  },
  "applicationType": "native",
  "architectures": [
    "x86_64",
    "aarch64"
  ],
  "entrypoint": {
    "executable": "bin/example",
    "arguments": []
  },
  "install": {
    "scope": "user",
    "mode": "bundled",
    "estimatedSize": 125829120
  },
  "permissions": [
    "network",
    "user-files-selected"
  ],
  "updates": {
    "enabled": true,
    "channel": "stable",
    "manifest": "https://example.com/releases/update.json",
    "allowSourceChange": true
  },
  "integration": {
    "desktopEntry": true,
    "categories": [
      "Utility"
    ],
    "fileAssociations": [
      {
        "extension": ".example",
        "mimeType": "application/x-example"
      }
    ]
  }
}
```

---

# Package Structure

The initial format could be a deterministic ZIP-compatible archive.

Example:

```text
ExampleApplication.lexe
├── lexe.json
├── signatures/
│   ├── manifest.sig
│   └── payload.sig
├── metadata/
│   ├── description.md
│   ├── license.txt
│   └── permissions.json
├── icons/
│   ├── 64.png
│   ├── 128.png
│   ├── 256.png
│   └── scalable.svg
├── payload/
│   └── application files
└── scripts/
    ├── migrate-user-data
    └── health-check
```

Installation scripts should be heavily restricted.

Where possible, installation behavior should be declarative rather than shell-script based.

---

# Security Model

Double-click installation is only useful if users can understand what they are trusting.

Lexe should include the following protections.

## Signed Packages

Publishers sign:

* the manifest;
* payload hashes;
* update metadata;
* source configuration.

## Reproducible Package Hashes

The package format should support deterministic builds so that independent parties can verify that two packages contain identical content.

## Permission Disclosure

Before installation, Lexe displays requested capabilities such as:

* network access;
* microphone;
* camera;
* notifications;
* selected files;
* all user files;
* removable storage;
* background execution;
* autostart;
* system service installation;
* device access.

These permissions may initially be informational where Linux cannot technically enforce them, but sandbox integrations can enforce them when available.

## Sandboxing

Applications may optionally or mandatorily launch through:

* Bubblewrap;
* Flatpak sandboxing;
* Landlock;
* namespaces;
* seccomp;
* portals;
* systemd user services.

## Update Ownership

A package should not be able to silently transfer update control to another domain or signing key.

Changing the signing key or update source should require:

* a valid key-rotation signature; or
* explicit user approval.

## Rollback

Lexe should preserve at least one previous application version by default.

When an update fails its health check, the runtime can restore the previous version.

---

# Updates

Lexe updates should be decentralized.

The runtime reads a signed update manifest from the user-approved source.

An update manifest may provide:

* the newest version;
* release channel;
* architecture-specific builds;
* hashes;
* signatures;
* delta updates;
* minimum Lexe Runtime version;
* migration instructions;
* rollback compatibility.

Users may select:

* automatic updates;
* notify before updating;
* manual updates;
* stable, beta, or nightly channels;
* preferred mirrors;
* pinned application versions.

The original developer does not need to run a centralized Lexe store.

---

# Installed Application Representation

After installation, Lexe creates:

* a standard `.desktop` launcher;
* application icons;
* an installation record;
* a launcher controlled by the Lexe Runtime;
* optional MIME and protocol associations.

The menu shortcut should point to a stable Lexe launcher rather than directly to a version-specific executable.

Example:

```text
lexe run com.example.application
```

This allows the runtime to:

* choose the active version;
* configure the sandbox;
* select Wine or another runtime;
* apply environment variables;
* record crashes;
* roll back failed updates;
* repair missing files.

A full `.lexe` file may also operate in portable mode without formal installation.

---

# Portable Mode

A user may choose:

> Run without installing

In portable mode:

* application files are extracted to a temporary or user-selected directory;
* system integration is not created;
* application data can remain beside the package or in a temporary profile;
* no permanent update source is registered unless approved.

Portable mode should be disabled when an application genuinely requires installation.

---

# Uninstallation

Lexe maintains a record of everything installed on behalf of an application.

Uninstalling should remove:

* application versions;
* launchers;
* icons;
* registered protocols;
* file associations;
* compatibility prefixes;
* application-specific runtimes;
* background services;
* autostart entries.

The user should separately choose whether to delete:

* application settings;
* documents;
* save files;
* caches;
* Wine prefixes;
* backups.

---

# User Interface

## Opening a `.lexe` File

The primary screen should show:

```text
Example Application
Published by Example Corporation
Version 1.4.2

Source:
Developer Repository

Application Type:
Native Linux — x86_64

Permissions:
Network access
Access to files you select

Installation:
Current user only
126 MB

Updates:
Automatically check the developer repository

[Advanced Options]             [Install]
```

## Advanced Options

Advanced users may configure:

* installation source;
* installation directory;
* runtime version;
* Wine prefix;
* sandbox profile;
* update channel;
* version pinning;
* environment variables;
* architecture emulation;
* portable mode;
* dependency source;
* system integration.

The simple path should remain simple, while Linux users retain full control.

---

# Command-Line Interface

The graphical application should be backed by a consistent CLI.

```bash
lexe install ExampleApplication.lexe
lexe run com.example.application
lexe update com.example.application
lexe update --all
lexe remove com.example.application
lexe repair com.example.application
lexe info ExampleApplication.lexe
lexe verify ExampleApplication.lexe
lexe source set com.example.application <source>
lexe rollback com.example.application
lexe list
```

This makes Lexe suitable for:

* desktop users;
* scripts;
* enterprise deployment;
* gaming systems;
* immutable Linux distributions;
* development environments.

---

# First Prototype Scope

The first prototype should deliberately remain narrow.

## Lexe 0.1

Support:

1. Opening `.lexe` files by double-clicking.
2. ZIP-based package structure.
3. JSON manifest.
4. Native Linux x86-64 applications.
5. Userspace installation.
6. Standard desktop entries and icons.
7. Ed25519 package signatures.
8. Hash verification.
9. Application launching through `lexe run`.
10. HTTPS update manifests.
11. Uninstallation and rollback.
12. A basic graphical installer.
13. A complete command-line interface.

Do not initially support:

* arbitrary root installation scripts;
* kernel drivers;
* every Linux package manager;
* all Wine configurations;
* Box64 or QEMU;
* full sandbox permission enforcement;
* delta updates;
* commercial licensing systems.

Those can be added after the native userspace flow is reliable.

---

# Lexe 0.2

Add:

* Wine applications;
* managed Wine prefixes;
* Flatpak and AppImage import;
* Bubblewrap sandbox profiles;
* portable execution;
* multiple update channels;
* private repositories;
* dependency bundles.

---

# Lexe 0.3

Add:

* ARM and cross-architecture execution;
* Box64 and FEX integration;
* delta updates;
* enterprise policies;
* graphical application management;
* repository browsing;
* developer publishing tools;
* package build reproducibility verification.

---

# Long-Term Goal

Lexe should become a universal Linux desktop application layer, not a mandatory centralized store.

A developer should be able to publish an application from their own infrastructure.

A distribution should be able to provide its own verified Lexe source.

A company should be able to operate a private repository.

A user should be able to mirror, archive, transfer, inspect, and choose where applications come from.

The final experience should be:

> Download. Double-click. Verify. Install. Launch.

Without giving up Linux ownership, openness, decentralization, or technical control.

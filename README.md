# Crossdeployqt

This is a tool that collects the dependencies and assets for a Qt 6 application so it is suitable for packaging & deployment.

It supports Linux, macOS & Windows(MingW) binaries, and can be viewed as an alternative for `windeployqt`, `macdeployqt` and offers a `linuxdeployqt`.

Crossdeployqt is used on a Linux host, and can deploy for Linux & Windows(MingW). It can technically deploy macOS on a Linux host if you have the SDK & Qt frameworks, in our usage we use a macOS host.

Packaging & installers for distribution is out of scope, use dedicated packaging tools like [Velopack](https://velopack.io).

Currently there is also no code-signing.
Webauthz Test Resource Service
==============================

This service stores all its data in memory, so every time you start
or restart the service, you have to start over with creating a new
account.

# Quick start

Install dependencies:

```
npm install
```

Start the server:

```
npm start
```

Open your browser:

```
http://localhost:29001
```

# Customize

You can change the port number by setting the `LISTEN_PORT` environment
variable before you run `npm start`.

In Linux:

```
export LISTEN_PORT=29001
```

In PowerShell:

```
$env:LISTEN_PORT="29001"
```

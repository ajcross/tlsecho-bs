# tlsecho

Simple tls test server that returns (and logs) info about the connection: headers, protocols and a bit more

## Build

build with 

```
go build -o tlsecho tlsecho.go
```

## Docker

docker image for amd64 and arm64 can be found at 

`docker.io/ajcross/tlsecho:latest`

## Usage

```
# ./tlsecho --help
Usage of ./tlsecho:
  -addr string
    	service address (default ":8443")
  -cert string
    	Certificate file
  -cn string
    	cn of the generated certificate (default "localhost")
  -envprefix string
    	environent variables prefix to return (default "TLSECHO")
  -key string
    	Certificate key file
  -set-cookie
    	set cookie (default true)
  -tls
    	tls (default true)
  -v	verbose (default true)
  -verbose
    	verbose (default true)
```

## Enviroment variables and kubernetes

tlsecho returns (and logs) environment variables that match a prefix. This can be use to report the node or the pod serving the request. 

For a Deployment definiton example (with no tls):

````
apiVersion: apps/v1
kind: Deployment
metadata:
  creationTimestamp: null
  namespace: foo
  labels:
    app: example
  name: example
spec:
  replicas: 1
  selector:
    matchLabels:
      app: example
  strategy: {}
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: example
    spec:
      containers:
      - image: docker.io/ajcross/tlsecho
        name: tlsecho
        ports:
        - containerPort: 8080
        resources: {}
        args: ["/app/tlsecho","--addr",":8080","-tls=false","--env-prefix=K_"]
        env:
          - name: K_NODE
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: K_POD_NAME
            valueFrom:
              fieldRef:
                fieldPath: metadata.name
          - name: K_POD_NS
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
          - name: K_POD_IP
            valueFrom:
              fieldRef:
                fieldPath: status.podIP
          - name: K_POD_SA
            valueFrom:
              fieldRef:
                fieldPath: spec.serviceAccountName


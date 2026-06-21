## Gateway Setup and Start Process

### I. Full Operation Setup and Start
This session describes the process to setup and start the full operation of IoT-Gateway, meaning it include:

1. IoT Gateway (Receive Data from Sensor, Process and Forward to Monitoring Stack)
2. Monitoring (Stack to Visualize and Monitor Data)
3. Fake_Sensor (Stack to generation fake data to gateway for testing)

---
#### 1. Prerequisites
For the setup to work properly, user need to follow these steps

1. Check the current IP of the machine and replace the user machine's IP into the subsequent.
    
    User can extract their machine IP by running

    ```shell
    ifconfig
    ```

    Machine IP usually remains as follows
    ```
    eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
    inet 10.185.71.215  netmask 255.255.224.0  broadcast 10.185.95.255
    inet6 fe80::c603:a8ff:fece:86ff  prefixlen 64  scopeid 0x20<link>
    ether c4:03:a8:ce:86:ff  txqueuelen 1000  (Ethernet)
    RX packets 146647  bytes 185525385 (185.5 MB)
    RX errors 0  dropped 0  overruns 0  frame 0
    TX packets 21119  bytes 22601597 (22.6 MB)
    TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
    ```

    Copy the machine IP in the inet section into these following line in corresponding file

    ``cert-generation.sh``
    ```shell
    # --- Server Details ---
    SERVER_CN="10.185.90.215" <-- Place your Ip here
    ```

    ``/fake_sensor/build/sensor1/test_sensor_data.sh``
    ```shell
    HOST="10.184.134.81" <-- Place your Ip here
    ```

    ``/fake_sensor/build/sensor2/test_sensor_data.sh``
    ```shell
    HOST="10.184.134.81" <-- Place your Ip here
    ```

    ``/fake_sensor/build/sensor3/test_sensor_data.sh``
    ```shell
    HOST="10.184.134.81" <-- Place your Ip here
    ```

    ``/fake_sensor/build/sensor4/test_sensor_data.sh``
    ```shell
    HOST="10.184.134.81" <-- Place your Ip here
    ```

2. Go to source directory and run this following command to grant permission to Docker service
    ```shell
    sudo chmod 777 -R .
    ```

---
#### 2. Start Process
First before starting any serivce, user need to run ``cert-generation.sh`` script to update certificate for SSL verification. Run
```shell
bash cert-generation.sh
```

Each service start with following command
```shell
docker compose build
docker compose up -d
```
The sequence to start each service is following:

1. gateway
2. monitoring
3. fake_sensor

> **Notice**: The service fake_sensor should only be started for a short period of time to prevent storage overflow
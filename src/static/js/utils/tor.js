

export function connectSocks5(proxyHost, proxyPort, targetHost, targetPort) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection({ host: proxyHost, port: proxyPort }, () => {
            console.log("Connected to SOCKS5 proxy");

            const authRequest = Buffer.from([0x05, 0x01, 0x00]);
            socket.write(authRequest);
        });

        socket.once("data", (data) => {
            if (data[0] !== 0x05 || data[1] !== 0x00) {
                return reject(new Error("SOCKS5 authentication failed"));
            }

            console.log("SOCKS5 authentication successful");

            let request;
            if (/^\d+\.\d+\.\d+\.\d+$/.test(targetHost)) {
                const ipParts = targetHost.split(".").map(Number);
                request = Buffer.alloc(10);

                request[0] = 0x05;
                request[1] = 0x01;
                request[2] = 0x00;
                request[3] = 0x01;
                Buffer.from(ipParts).copy(request, 4);
                request.writeUInt16BE(targetPort, 8);
            } else {
                const hostBuffer = Buffer.from(targetHost, "utf8");
                request = Buffer.alloc(7 + hostBuffer.length);

                request[0] = 0x05;
                request[1] = 0x01;
                request[2] = 0x00;
                request[3] = 0x03;
                request[4] = hostBuffer.length;
                hostBuffer.copy(request, 5);
                request.writeUInt16BE(targetPort, 5 + hostBuffer.length);
            }

            socket.write(request);
        });

        socket.once("data", (data) => {
            if (data.length < 2 || data[1] !== 0x00) {
                return reject(new Error("SOCKS5 connection failed"));
            }

            console.log("SOCKS5 connection established");
            resolve(socket);
        });

        socket.on("error", reject);
    });
}
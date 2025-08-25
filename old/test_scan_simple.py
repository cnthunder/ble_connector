import asyncio
from ble_serial.scan import main as scanner

async def main():
    ### general scan
    ADAPTER = "hci0"
    SCAN_TIME = 5 #seconds
    SERVICE_UUID = None # optional filtering
    VERBOSE = False

    devices = await scanner.scan(ADAPTER, SCAN_TIME, SERVICE_UUID)
    print(devices)
    print("newline") # newline
    scanner.print_list(devices, VERBOSE)


if __name__ == "__main__":
    asyncio.run(main())
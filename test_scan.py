import asyncio
from ble_serial.scan import main as scanner

async def main():
    ### general scan
    ADAPTER = "hci0"
    SCAN_TIME = 5 #seconds
    SERVICE_UUID = None # optional filtering
    VERBOSE = False

    devices = await scanner.scan(ADAPTER, SCAN_TIME, SERVICE_UUID)

    print("newline") # newline
    scanner.print_list(devices, VERBOSE)

    # manual indexing of devices dict
    dev_list = list(devices.values())
    print("list0")
    print(dev_list[0])

    ### deep scan get's services/characteristics
    DEVICE = "B4:56:5D:20:53:1C"
    services = await scanner.deep_scan(DEVICE, devices)

    scanner.print_details(services)
    print() # newline

    # manual indexing by uuid
    print("fff0")
    print(services.get_service('0000fff0-0000-1000-8000-00805f9b34fb'))
    print("fff1")
    print(services.get_characteristic('0000ffe1-0000-1000-8000-00805f9b34fb'))
    # or by handle
    print("16")
    print(services.services)
    print("17")
    print(services.characteristics)



if __name__ == "__main__":
    asyncio.run(main())
import os
import time

def main():
    try:
        os.remove("/etc/pmon.d/neutron-avr-agent.conf")
    except: 
        pass 

    while True:
        time.sleep(100)

if __name__ == "__main__":
    main()

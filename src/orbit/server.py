from __future__ import annotations
import time

from orbit.service.pki import PKIService

import multiprocessing

def start_pki():
    pki_service = PKIService()
    pki_service.run()
    
def start_node():
    pass

def start_schedule():
    print("Scheduling...")
    while True:
        time.sleep(1)

class OrbitServer():
    def __init__(self):
        self.pki_process = multiprocessing.Process(target=start_pki)
        self.node_process = multiprocessing.Process(target=start_node)
        self.schedule_process = multiprocessing.Process(target=start_schedule)

    def start_all(self):
        self.pki_process.start()
        self.node_process.start()
        self.schedule_process.start()

    def stop_all_processes(self):
        self.pki_process.terminate()
        self.node_process.terminate()
        self.schedule_process.terminate()

def main():
    server = OrbitServer()
    server.start_all()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop_all_processes()
        print("Orbit server stopped.")
        exit(0)

    
        
        
    
    



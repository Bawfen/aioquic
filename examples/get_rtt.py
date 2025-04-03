import asyncio
import time
from typing import List, Dict
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
import ssl
import json
from dataclasses import dataclass, asdict
import logging
from parse_rtt_pcap import analyze_rtt
from tcpdump import TCPDump
import os
import subprocess


INTERFACE_NAME = "ens4"


@dataclass
class QUICMeasurement:
    domain: str
    rtt_ms: float
    success: bool
    error: str = None


class QUICRTTMeasurer:
    def __init__(self, domains: List[str], max_concurrent_tasks: int = 10):
        self.domains = domains
        self.results: List[QUICMeasurement] = []
        self.max_concurrent_tasks = max_concurrent_tasks
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)

    async def measure_single_domain(self, domain: str) -> QUICMeasurement:
        async with self.semaphore:  # Limit concurrent connections
            self.logger.info(f"Measuring QUIC RTT for {domain}")

            # Configure QUIC
            configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
            configuration.idle_timeout = 3

            # Create SSL context
            # configuration.verify_mode = ssl.CERT_NONE

            # start tcpdump here

            try:
                
                

                # Attempt QUIC connection
                async with connect(
                    domain,
                    443,
                    configuration=configuration,
                    # ssl_context=ssl_context,
                    wait_connected=True,
                ) as connection:
                    # this might be getting multiple RTTs because of handshake
                    # take pcaps and look at one request and response
                    # this should remove the problem of app layer delays and make sure we only get one RTT
                    
                    # print(analyze_rtt(tcpdump_out_file))
                    # if os.path.exists(tcpdump_out_file):
                    #     subprocess.run(f"sudo rm {tcpdump_out_file}".split(" "))

                    ## todo return the rtt returned from analyze function
                    return None
                    

            except Exception as e:
                # raise e
                self.logger.error(f"Error measuring {domain}")
                return QUICMeasurement(
                    domain=domain, rtt_ms=-1, success=False, error=str(e)
                )
            

    async def measure_all(self):

        tcpdump_out_file = f"pcap.pcap"
        if not PARSE_ONLY:
            tcpd = TCPDump(INTERFACE_NAME, tcpdump_out_file)
            tcpd.start()
            time.sleep(2)
            tasks = [self.measure_single_domain(domain) for domain in self.domains]
            results = await asyncio.gather(*tasks)
            time.sleep(2)
            tcpd.stop()
        stats = analyze_rtt(tcpdump_out_file, self.domains)
        for domain, stats in stats.items():
            results.append(QUICMeasurement(domain=domain,rtt_ms=stats['median'], success=True))
        self.results = [result for result in results if result is not None]
        self.logger.info(f"Completed measurements for {len(self.domains)} domains")

    def save_results(self, filename: str = "quic_rtt_results_20000_verify_3.json"):
        with open(filename, "w") as f:
            json.dump([asdict(result) for result in self.results], f, indent=2)
        self.logger.info(f"Results saved to {filename}")

    def print_results(self):
        print("\nQUIC RTT Measurement Results:")
        print("-" * 60)
        print(f"{'Domain':<30} {'RTT (ms)':<10} {'Status':<20}")
        print("-" * 60)

        for result in self.results:
            status = "Success" if result.success else f"Failed: {result.error}"
            rtt = f"{result.rtt_ms:.2f}" if result.success else "N/A"
            print(f"{result.domain:<30} {rtt:<10} {status:<20}")


PARSE_ONLY=False

async def main():
    # Example domains to test
    # domains = ["biharmasti.net"]
    # domains = ["ads.google.com"]
    original_list = open("examples/sites_top_20000.csv", "r").read().splitlines()
    domains = [x.split(",")[0] for x in original_list]

    measurer = QUICRTTMeasurer(domains, max_concurrent_tasks=10)
    await measurer.measure_all()
    # measurer.print_results()
    measurer.save_results()


if __name__ == "__main__":
    asyncio.run(main())

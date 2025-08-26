#!/usr/bin/env python3
 
import argparse
import ctypes
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
 
# Windows API constants for volume keys
KEYEVENTF_KEYUP = 0x0002
VK_VOLUME_UP = 0xAF    # Virtual key code for Volume Up
VK_VOLUME_DOWN = 0xAE  # Virtual key code for Volume Down
 
class LoggerConfig:
    """Configure logging settings for the application"""
    @staticmethod
    def setup_logger(log_file: str, debug: bool = False) -> None:
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=level,
            format='[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] %(message)s',
            handlers=[
                logging.FileHandler(log_file, mode="w", encoding='utf-8'),
                logging.StreamHandler(sys.stdout),
            ],
        )
        logging.debug("Logger initialized")
 
class KeepAwake:
    """Keep Windows awake by simulating volume key presses"""
    def __init__(self, interval: int = 60):
        """
        Initialize KeepAwake
         
        Args:
            interval: Time interval between key presses in seconds
        """
        self.interval = interval
        self.user32 = ctypes.windll.user32
        self.start_time = datetime.now()
        self.toggle = True  # Used to alternate between volume up and down
         
    def press_key(self) -> None:
        """
        Simulate pressing and releasing volume keys
        Alternates between Volume Up and Volume Down to maintain current volume level
        """
        try:
            # Choose which volume key to press
            key = VK_VOLUME_UP if self.toggle else VK_VOLUME_DOWN
             
            # Press the key
            self.user32.keybd_event(key, 0, 0, 0)
            # Release the key
            self.user32.keybd_event(key, 0, KEYEVENTF_KEYUP, 0)
             
            logging.debug(f"Key press simulated successfully: {'Volume Up' if self.toggle else 'Volume Down'}")
             
            # Toggle for next time
            self.toggle = not self.toggle
             
        except Exception as e:
            logging.error(f"Failed to simulate key press: {str(e)}")
            raise
             
    def run(self) -> None:
        """Run the keep-awake loop"""
        logging.info(f"Keep-awake started at {self.start_time}")
        logging.info(f"Press Ctrl+C to stop")
         
        try:
            while True:
                self.press_key()
                elapsed = datetime.now() - self.start_time
                logging.info(f"Running for {elapsed} (Press Ctrl+C to stop)")
                time.sleep(self.interval)
                 
        except KeyboardInterrupt:
            end_time = datetime.now()
            elapsed = end_time - self.start_time
            logging.info(f"Keep-awake stopped at {end_time}")
            logging.info(f"Total running time: {elapsed}")
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")
            raise
 
def main():
    parser = argparse.ArgumentParser(
        description='Keep Windows awake by simulating periodic volume key presses'
    )
    parser.add_argument(
        '--interval', '-i',
        type=int,
        default=600,
        help='Interval between key presses in seconds (default: 600)'
    )
    parser.add_argument(
        '--log-file', '-l',
        default='keep_awake.log',
        help='Path to the log file (default: keep_awake.log)'
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug logging'
    )
     
    args = parser.parse_args()
     
    try:
        # Setup logging
        LoggerConfig.setup_logger(args.log_file, args.debug)
         
        # Create and run keep-awake instance
        keep_awake = KeepAwake(args.interval)
        keep_awake.run()
         
    except Exception as e:
        logging.error(f"Program failed: {str(e)}")
        sys.exit(1)
 
if __name__ == '__main__':
    main()

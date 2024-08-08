import hashlib
import exiftool
import os
import re
from scapy.all import rdpcap, sniff, IP, TCP, Raw
import pytsk3
import pyewf

class ForensicTool:
    def __init__(self):
        pass

    def extract_ip_urls_from_pcap(self, pcap_file):
        try:
            packets = rdpcap(pcap_file)
            ips = set()
            urls = set()

            for packet in packets:
                if packet.haslayer(IP):
                    ips.add(packet[IP].src)
                    ips.add(packet[IP].dst)
                if packet.haslayer(TCP) and packet.haslayer(Raw):
                    payload = packet[Raw].load
                    urls.update(re.findall(rb'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', payload))

            return ips, urls
        except Exception as e:
            print(f"Error extracting IPs and URLs: {e}")
            return set(), set()

    def calculate_hash(self, file_path, hash_type='md5'):
        try:
            hash_func = getattr(hashlib, hash_type)()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return None

    def get_metadata(self, file_path):
        try:
            with exiftool.ExifTool() as et:
                metadata = et.get_metadata(file_path)
            return metadata
        except Exception as e:
            print(f"Error getting metadata: {e}")
            return None

    def monitor_traffic(self, interface, packet_count=10):
        try:
            packets = sniff(iface=interface, count=packet_count)
            packets.summary()
        except Exception as e:
            print(f"Error monitoring traffic: {e}")

    def extract_files_from_image(self, image_path, output_folder):
        try:
            if not os.path.exists(output_folder):
                os.makedirs(output_folder)

            filenames = pyewf.glob(image_path)
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)

            img_info = pytsk3.Img_Info(image=ewf_handle)
            fs_info = pytsk3.FS_Info(img_info)

            for dir in fs_info.open_dir(path="/"):
                for file in dir:
                    output_path = os.path.join(output_folder, file.info.name.name.decode())
                    with open(output_path, 'wb') as out_file:
                        file_data = file.read_random(0, file.info.meta.size)
                        out_file.write(file_data)
        except Exception as e:
            print(f"Error extracting files from image: {e}")

    def string_search(self, file_path, search_string):
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                matches = re.findall(search_string, content)
            return matches
        except Exception as e:
            print(f"Error performing string search: {e}")
            return []

    def analyze_log_files(self, log_file, keywords):
        try:
            with open(log_file, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    if any(keyword in line for keyword in keywords):
                        print(line)
        except Exception as e:
            print(f"Error analyzing log files: {e}")

    def crack_hash(self, hash_value, hash_type, wordlist_path):
        try:
            with open(wordlist_path, 'r') as file:
                for line in file:
                    word = line.strip()
                    hash_func = getattr(hashlib, hash_type)()
                    hash_func.update(word.encode('utf-8'))
                    if hash_func.hexdigest() == hash_value:
                        return word
            return None
        except Exception as e:
            print(f"Error cracking hash: {e}")
            return None

# Interactive Menu
def main():
    tool = ForensicTool()
    while True:
        print("\nForensic Tool Menu:")
        print("1. Extract IP address and URLs from pcap file")
        print("2. Calculate hash of a file")
        print("3. Get metadata information using ExifTool")
        print("4. Monitor network traffic")
        print("5. Extract all files from a forensic image")
        print("6. String search inside a file")
        print("7. Analyze log files by defining keywords")
        print("8. Crack hash using wordlist")
        print("9. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            pcap_file = input("Enter the path to the pcap file: ")
            ips, urls = tool.extract_ip_urls_from_pcap(pcap_file)
            print("Extracted IP addresses:", ips)
            print("Extracted URLs:", urls)

        elif choice == '2':
            file_path = input("Enter the path to the file: ")
            hash_type = input("Enter hash type (md5/sha1/sha256): ").lower()
            hash_value = tool.calculate_hash(file_path, hash_type)
            print(f"{hash_type.upper()} Hash: {hash_value}")

        elif choice == '3':
            file_path = input("Enter the path to the file: ")
            metadata = tool.get_metadata(file_path)
            print("Metadata:", metadata)

        elif choice == '4':
            interface = input("Enter the network interface: ")
            packet_count = int(input("Enter the number of packets to capture: "))
            tool.monitor_traffic(interface, packet_count)

        elif choice == '5':
            image_path = input("Enter the path to the forensic image: ")
            output_folder = input("Enter the output folder path: ")
            tool.extract_files_from_image(image_path, output_folder)
            print(f"Files extracted to {output_folder}")

        elif choice == '6':
            file_path = input("Enter the path to the file: ")
            search_string = input("Enter the search string: ")
            matches = tool.string_search(file_path, search_string)
            print("Matches found:", matches)

        elif choice == '7':
            log_file = input("Enter the path to the log file: ")
            keywords = input("Enter the keywords to search (comma-separated): ").split(',')
            tool.analyze_log_files(log_file, keywords)

        elif choice == '8':
            hash_value = input("Enter the hash value: ")
            hash_type = input("Enter hash type (md5/sha1/sha256): ").lower()
            wordlist_path = input("Enter the path to the wordlist: ")
            cracked = tool.crack_hash(hash_value, hash_type, wordlist_path)
            if cracked:
                print(f"Hash cracked! The value is: {cracked}")
            else:
                print("Hash not found in the wordlist.")

        elif choice == '9':
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

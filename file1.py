import pyzeek

# Define a function to handle DNS log data
def handle_dns_log(data):
    # Extract the relevant fields from the data
    id_orig_h = data['id.orig_h']
    id_resp_h = data['id.resp_h']
    query = data['query']

    # Process the data as needed (e.g. extract features, make predictions, etc.)

# Capture and parse DNS log data in real-time using PyZeek
for log in dns_log('/home/logs/current/dns.log', tail=True):
    # Pass the DNS log data to your handling function
    handle_dns_log(log)





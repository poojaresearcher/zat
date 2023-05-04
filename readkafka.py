import os
from kafka import KafkaProducer

# Kafka broker address
bootstrap_servers = 'localhost:9092'

# Kafka topic to produce messages
topic = 'zeek_predictions'

# Path to Zeek log files
log_files_path = '/opt/zeek/logs/current/dns.log'

# Create Kafka producer instance
producer = KafkaProducer(bootstrap_servers=bootstrap_servers)

# Read Zeek log files
for file_name in os.listdir(log_files_path):
    if file_name.endswith('.log'):
        file_path = os.path.join(log_files_path, file_name)
        with open(file_path, 'r') as file:
            # Process each line of the log file
            for line in file:
                # Preprocess and extract relevant features from the log line
                # Replace the following preprocessing and feature extraction steps with your own implementation
                processed_data = preprocess_and_extract_features(line)

                # Convert processed data to bytes
                message = str(processed_data).encode('utf-8')

                # Produce the message to the Kafka topic
                producer.send(topic, message)

# Close the Kafka producer
producer.close()

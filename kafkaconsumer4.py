from kafka import KafkaConsumer, KafkaProducer
import json
import numpy as np
from keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Load the trained model
model = load_model('my_model.h5')

# Define Kafka consumer and producer
consumer = KafkaConsumer('input_topic', bootstrap_servers='localhost:9092',
                         value_deserializer=lambda x: json.loads(x.decode('utf-8')))

producer = KafkaProducer(bootstrap_servers='localhost:9092',
                         value_serializer=lambda x: json.dumps(x).encode('utf-8'))

# Kafka topics for input and output
input_topic = 'dns1'
output_topic = 'prediction'

for message in consumer:
    dns_message = message.value
    domain = dns_message.get('domain', '')
    print("Domain:", domain)

    # Preprocess the domain
    sequence = [c for c in domain]
    int_sequence = [char_to_int.get(c, 0) for c in sequence]
    padded_sequence = pad_sequences([int_sequence], maxlen=max_sequence_length)

    # Make prediction using the model
    prediction = model.predict(padded_sequence)[0]
    prediction_label = 'DGA' if prediction >= 0.5 else 'Legitimate'
    print("Prediction:", prediction_label)

    # Prepare the prediction message
    prediction_message = {
        'domain': domain,
        'prediction': prediction_label
    }

    # Publish the prediction message to output topic
    producer.send(output_topic, value=prediction_message)
    producer.flush()

consumer.close()
producer.close()

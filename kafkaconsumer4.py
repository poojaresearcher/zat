from kafka import KafkaConsumer, KafkaProducer
import json
import pandas as pd
import numpy as np
from keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

model = load_model('my_model.h5')

consumer = KafkaConsumer('dns1', bootstrap_servers=['localhost:9092'],
                         value_deserializer=lambda x: json.loads(x.decode('utf-8')))

producer = KafkaProducer(bootstrap_servers=['localhost:9092'],
                         value_serializer=lambda x: json.dumps(x).encode('utf-8'))

predictions_topic = 'prediction'

for message in consumer:
    dns_message = message.value
    query = dns_message.get('query', 'default_value')
    print("Query:", query)

    # Convert query to sequence
    sequence = [c for c in query]

    # Convert sequence to integer sequence
    int_sequence = [char_to_int.get(c, 0) for c in sequence]

    # Pad sequence to match the model's input length
    padded_sequence = pad_sequences([int_sequence], maxlen=max_sequence_length)

    # Predict with the classifier model
    domain_prediction = model.predict(padded_sequence)[0]
    print("Domain Prediction:", domain_prediction)

    # Prepare prediction output message
    prediction_message = {
        'query': query,
        'DGA domain prediction': 'DGA' if domain_prediction >= 0.5 else 'Legitimate'
    }

    # Publish prediction output to Kafka topic
    producer.send(predictions_topic, value=prediction_message)
    producer.flush()

consumer.close()
producer.close()

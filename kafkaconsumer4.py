import pandas as pd
import numpy as np
from keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

model = load_model('my_model.h5')

consumer = KafkaConsumer('dns1', bootstrap_servers=['localhost:9092'],
                         value_deserializer=lambda x: json.loads(x.decode('utf-8')))

producer = KafkaProducer(bootstrap_servers=['localhost:9092'],
                        value_serializer=lambda x: json.dumps(x).encode('utf-8'))

for message in consumer:
    dns_message = message.value
    query = dns_message.get('query', 'default_value')
    print(query)

    # Preprocess and extract features
    features = extract_features(query)
    print(features)
   
        # Convert domain feature to a numeric array
    domain_feature_values = list(features.values())
    domain_feature_array = np.array(domain_feature_values).reshape(1, -1)

        # Predict with the classifier model
    domain_prediction = classifier.predict(domain_feature_array)[0]
    print("Domain Prediction:", domain_prediction)
    
if domain_prediction == 'DGA':
    # Prepare prediction output message
    prediction_message = {
        'query': query,
        'DGA domain prediction': domain_prediction
    }

    predictions = 'output_topic'
    # Publish prediction output to Kafka topic
    producer.send('predictions', value=prediction_message)
    producer.flush()
    
    

consumer.close()
producer.close()



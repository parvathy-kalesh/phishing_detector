from feature_extractor import extract_features

url = "http://192.0.2.0:8080/confirm"
features_df = extract_features(url)
print(features_df[['having_IP_Address', 'port']])


# rest of your code follows...






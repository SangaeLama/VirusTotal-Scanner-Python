#v1.1
#date : 2022/12/03
#author: Sangay Lama
#This script takes a MalwareBazar info file (json) as an argument and scans each samples from the json file against VT.
#Might later add support for multiple VT clients for breaking the VT API request limit.

import vt
import json
import pandas as pd
import sys

#create an API client with your API key first
client=vt.Client("YOUR_API_KEY")

#reading the input file given by the user as argument
input_file = sys.argv[1]

#open the json file given by Malware bazaar
with open(f"{input_file}") as json_file:
    data = json.load(json_file)
    #flattening the json data and making a dataframe out of it.
    df = pd.json_normalize(data, 'data')

#getting just the sha256 hashes from each of the malware samples
sha256_hashes = df['sha256_hash']

#creating an empty list to store the VT scores
scores = []

#looping through each hash from the df to make a scan request based on the hash
for i in sha256_hashes:
    #making the API request for scanning files
    file = client.get_object(f"/files/{i}")
    """
    the scan result stored in file has a lot more information
    but for now we only need number of Engines flagging the file as malicious
    """
    malcount = file.last_analysis_stats.get('malicious')
    #appending the VT scores to the list we created earlier
    scores.append(malcount)
    print(f"VT Score of {i} is {malcount}")

#Adding a new column to the dataframe called VT_Score with the values of the list.
df['VT_Score'] = scores

#creating a json out of the Dataframe
df.to_json(rf'./{input_file}&scores.json', orient='records')

#creating a new Dataframe with just the hash and the dataframe
new_df = df[["sha256_hash","VT_Score"]].copy()
print (new_df)

#exporting the new dataframe to a json file.
new_df.to_json(rf'./{input_file}_scores.json', orient='records')






"""
with open('./hashes.txt') as hashes:
    for i in hashes:
        print(f"{i} file is being scanned and its score is ")
        file = client.get_object(f"/files/{i}")
        malcount = file.last_analysis_stats.get('malicious')
        print(malcount)
        print("\n")

"""

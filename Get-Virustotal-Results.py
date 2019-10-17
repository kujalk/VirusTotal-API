#Developer - K.Janarthanan
#Date - 20/9/2019
#Purpose - 
    #Searching files by hash values
    #Getting virus total results
    #Getting AV labels in the dictionary

import csv
import requests
import time

#Configure parameters
source_csv="souce-file.csv"
api_key='apikey'
final_csv="Final-Results01.csv"

#Reading CSV file
all_files=[]

url = 'https://www.virustotal.com/vtapi/v2/file/report'

#Pass the extracted CSV file from Hybrid-Analysis
with open(source_csv) as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count=0
    no_results=0

    for row in csv_reader:

        my_dic={}

        if (line_count==0):
            line_count+=1

        else:
            
            my_dic['SHA256_Value']=row[0]

            #Calling API
            try:
                params = {'apikey': api_key, 'resource': row[0]}

                response = requests.get(url, params=params)

                answer=response.json()

                print("Detected/Total : "+str(answer['positives'])+"/"+str(answer['total']))
                print("SHA256 value : "+str(answer['sha256']))
                print("AV Results -> \n")

                av=answer['scans']

                final_store=[]
                for key in av.keys():

                    store_dc={}

                    if(str(answer['scans'][key]['detected'])=="True"):
                        store_dc['AV']=key
                        store_dc['Result']=str((answer['scans'][key]['result']))
                        final_store.append(store_dc)
                        
                print(str(final_store)+"\n")

                my_dic['Score']=str(answer['positives'])+"/"+str(answer['total'])
                my_dic['AV_Labels']=final_store

                #Only 4 APIs are allowed in 1 minute
                time.sleep(15)

            except:
                my_dic['Score']="No Score"
                my_dic['AV_Labels']="No Results"

                print("No results found from Virus Total\n")
                no_results+=1
                time.sleep(15)

            line_count+=1

        all_files.append(my_dic)

csv_file.close()

#Write to the CSV file
csv_columns=['SHA256_Value','Score','AV_Labels']

try:
    with open(final_csv,'a',newline='') as csvfile:
        writer=csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()

        for data in all_files:
            writer.writerow(data)

except:
    print("Error in creating CSV file")

print("\nTotal Files : "+str(line_count-1))
print("Files not found in VirusTotal : "+str(no_results))
print("Script completed !!!")

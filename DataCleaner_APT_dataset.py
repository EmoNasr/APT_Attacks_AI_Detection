import pandas as pd
from sklearn.preprocessing import StandardScaler
import os 

def cleanner_apt(url):

    ## Mapping Target Values
    attack_vectors = {
        'Benign':0,
        'BENIGN':0,
        'Reconnaissance':1,
        'Establish Foothold':2,
        'Lateral Movement':3,
        'Internal Reconnaissance':4,
        'Data Exfiltration':5,
        'Cover Up':6
    }

    ## Mapping The Content Of A Target Values
    attacksType_to_values = {
        'BENIGN':0,
        'Network Scan':1,
        'Account Discovery':2,
        'Directory Bruteforce':3,
        'Web Vulnerability Scan':4,
        'Normal':5,
        'Account Bruteforce':6,
        'Backdoor':7,
        'SQL Injection':8,
        'CSRF':9,
        'Malware Download':10,
        'Privilege Escalation':11,
        'Command Injection':12,
        'Data Exfiltration':13
    }


    #Reading Data
    df = pd.read_csv(url)
    print(df.head(1))

    #Droping unneeded colomns
    colums_to_drop = ['Flow ID','Src IP','Dst IP','Timestamp']
    df.drop(columns=colums_to_drop,inplace=True)
    df.shape

    #Label Encoding For STAGE Column And Make It As Target
    print("Stage: \n",df['Stage'].value_counts(),'\n')
    df['Stage'].replace(attack_vectors,inplace=True)
    targets = df[['Stage']]
    print(targets)

    #Label Encoding For Activity Column
    print("Activity: \n",df['Activity'].value_counts(),'\n')
    df['Activity'].replace(attacksType_to_values,inplace=True)
    type_of_attack = df[['Activity']]
    print("Activity: \n",df['Activity'].value_counts())

    #Normalized Dataset
    df = df.astype(float)
    df.dtypes
    #columns = df.select_dtypes(include='number')
    #scaler = StandardScaler()
    #scaler.fit(columns)
    #df[columns.columns] = scaler.transform(columns)

    df['Stage'] = targets
    df['Activity'] = type_of_attack
    print(df.head(10))

    return df

if __name__=="__main__":

    dataframes_list = []
    files = os.listdir('N:\AI_ML_RL\APT_dataset\dataset_\csv')
    os.chdir('N:\AI_ML_RL\APT_dataset\dataset_\csv')
    for file in files:
        if file.endswith('csv'):
            df = cleanner_apt(file)
            #print(file)
            dataframes_list.append(df)

# Concatenate the DataFrames in the list
result_df = pd.concat(dataframes_list)

# Write the concatenated DataFrame to a CSV file
result_df.to_csv('N:\AI_ML_RL\APT_dataset\datacleaningcleanedDataAndNormalize.csv', index=False)

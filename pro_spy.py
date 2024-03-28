# -*- coding: utf-8 -*-
"""
Created on Fri Oct 28 10:17:16 2022

@author: bisha
"""

# -*- coding: utf-8 -*-
"""
Created on Wed Oct 26 11:10:15 2022

@author: bisha
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import time
import warnings
warnings.filterwarnings('ignore')

wcols = """duration,protocol_type,service,flag,src_bytes,dst_bytes,land,wrong_fragment,urgent,hot,num_failed_logins,logged_in,num_compromised,root_shell,su_attempted,num_root,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_host_login,is_guest_login,count,srv_count,serror_rate,srv_serror_rate,rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,dst_host_same_srv_rate,dst_host_diff_srv_rate,dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,dst_host_serror_rate,dst_host_srv_serror_rate,dst_host_rerror_rate,dst_host_srv_rerror_rate,label"""

cols=[]
for c in wcols.split(','):
    if(c.strip()):
       cols.append(c.strip())
#print(len(cols))

data = pd.read_csv(".\\kddcup.data_10_percent_corrected", names=cols)
# print(data)

attack = {'normal': 'normal','back': 'dos','buffer_overflow': 'u2r','ftp_write': 'r2l','guess_passwd': 'r2l','imap': 'r2l','ipsweep': 'probe','land': 'dos','loadmodule': 'u2r','multihop': 'r2l','neptune': 'dos','nmap': 'probe','perl': 'u2r','phf': 'r2l','pod': 'dos','portsweep': 'probe','rootkit': 'u2r','satan': 'probe','smurf': 'dos','spy': 'r2l','teardrop': 'dos','warezclient': 'r2l','warezmaster': 'r2l',}

result = {'normal': 'No','back': 'Yes','buffer_overflow': 'Yes','buffer_overflow': 'Yes','ftp_write': 'Yes','guess_passwd': 'Yes','imap': 'Yes','ipsweep': 'Yes','land': 'Yes','loadmodule': 'Yes','multihop': 'Yes','neptune': 'Yes','nmap': 'Yes','perl': 'Yes','phf': 'Yes','pod': 'Yes','portsweep': 'Yes','rootkit': 'Yes','satan': 'Yes','smurf': 'Yes','spy': 'Yes','teardrop': 'Yes','warezclient': 'Yes','warezmaster': 'Yes',}

path = ".\\kddcup.data_10_percent_corrected"
df = pd.read_csv(path,names=cols)
df['Attack_Type'] = df.label.apply(lambda r:attack[r[:-1]])
df['State'] = df.label.apply(lambda r:result[r[:-1]])
#df.head()

#df.shape

#df['label'].value_counts()

#df['Attack_Type'].value_counts()

#df['State'].value_counts()

#df.dtypes

#df.isnull().sum()

num_cols = df._get_numeric_data().columns
#print(num_cols)
cate_cols = list(set(df.columns)-set(num_cols))
cate_cols.remove('label')
cate_cols.remove('Attack_Type')
cate_cols.remove('State')
#print(cate_cols)

def bar_graph(feature):
    df[feature].value_counts().plot(kind="bar")
    
#bar_graph('protocol_type')
#plt.figure(figsize=(15,3))
#bar_graph('service')
#bar_graph('flag')
#bar_graph('logged_in')
#bar_graph('label')
#bar_graph('Attack_Type')
#bar_graph('State')

# df = df.dropna('cols')
# df = df[[col for col in df if df[col].nunique() > 1]]
# -----------------------------------------------------------
for col in df.columns:
    if len(df[col].unique()) == 1:
        df.drop(col,inplace=True,axis=1)
# ------------------------------------------------------------
corr = df.corr()
plt.figure(figsize=(15,12))
sns.heatmap(corr, cmap='plasma', annot=True, cbar=True, linewidths=1, linecolor='black')
plt.show()


#df['num_root'].corr(df['num_compromised'])
#df['srv_serror_rate'].corr(df['serror_rate'])
#df['srv_count'].corr(df['count'])
#df['srv_rerror_rate'].corr(df['rerror_rate'])
#df['dst_host_same_srv_rate'].corr(df['dst_host_srv_count'])
#df['dst_host_srv_serror_rate'].corr(df['dst_host_serror_rate'])
#df['dst_host_srv_rerror_rate'].corr(df['dst_host_rerror_rate'])
#df['dst_host_same_srv_rate'].corr(df['same_srv_rate'])
#df['dst_host_srv_count'].corr(df['same_srv_rate'])
#df['dst_host_same_src_port_rate'].corr(df['srv_count'])
#df['dst_host_serror_rate'].corr(df['serror_rate'])
#df['dst_host_serror_rate'].corr(df['srv_serror_rate'])
#df['dst_host_srv_serror_rate'].corr(df['serror_rate'])
#df['dst_host_srv_serror_rate'].corr(df['srv_serror_rate'])
#df['dst_host_rerror_rate'].corr(df['rerror_rate'])
#df['dst_host_rerror_rate'].corr(df['srv_rerror_rate'])
#df['dst_host_srv_rerror_rate'].corr(df['rerror_rate'])
#df['dst_host_srv_rerror_rate'].corr(df['srv_rerror_rate'])

#This variable is highly correlated with num_compromised and should be ignored for analysis.
#(Correlation = 0.9938277978738366)
df.drop('num_root',axis = 1,inplace = True)

#This variable is highly correlated with serror_rate and should be ignored for analysis.
#(Correlation = 0.9983615072725952)
df.drop('srv_serror_rate',axis = 1,inplace = True)

#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9947309539817937)
df.drop('srv_rerror_rate',axis = 1, inplace=True)

#This variable is highly correlated with srv_serror_rate and should be ignored for analysis.
#(Correlation = 0.9993041091850098)
df.drop('dst_host_srv_serror_rate',axis = 1, inplace=True)

#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9869947924956001)
df.drop('dst_host_serror_rate',axis = 1, inplace=True)

#This variable is highly correlated with srv_rerror_rate and should be ignored for analysis.
#(Correlation = 0.9821663427308375)
df.drop('dst_host_rerror_rate',axis = 1, inplace=True)

#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9851995540751249)
df.drop('dst_host_srv_rerror_rate',axis = 1, inplace=True)

#This variable is highly correlated with srv_rerror_rate and should be ignored for analysis.
#(Correlation = 0.9865705438845669)
df.drop('dst_host_same_srv_rate',axis = 1, inplace=True)


#df.head()
#df.shape
#df.columns

df_std = df.std(numeric_only=True)
df_std = df_std.sort_values(ascending = True)
#print(df_std)

#df['protocol_type'].value_counts()
#print(df['protocol_type'])
promap = {'icmp':0,'tcp':1,'udp':2}
df['protocol_type'] = df['protocol_type'].map(promap)
#print(df['protocol_type'])

#df['flag'].value_counts()
#print(df['flag'])
flag_map = {'SF':0,'S0':1,'REJ':2,'RSTR':3,'RSTO':4,'SH':5 ,'S1':6 ,'S2':7,'RSTOS0':8,'S3':9 ,'OTH':10}
df['flag'] = df['flag'].map(flag_map)
#print(df['flag'])

#df.head()

df.drop('service',axis = 1,inplace= True)
#df.head()
#print(df.shape)
#df.dtypes
df = df.drop(['label',], axis='columns')
df = df.drop(['State',], axis='columns')
# prev line is executed early and label column is deleted

#df.columns
#df.shape


from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, matthews_corrcoef, f1_score, precision_score, recall_score, cohen_kappa_score, log_loss, roc_auc_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report




def matrix(Y_test,Y_test_pred):
    # Calculate the confusion matrix
    conf_matrix = confusion_matrix(y_true=Y_test, y_pred=Y_test_pred)
    # Print the confusion matrix using Matplotlib
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.matshow(conf_matrix, cmap=plt.cm.Blues, alpha=0.3)
    for i in range(conf_matrix.shape[0]):
        for j in range(conf_matrix.shape[1]):
            ax.text(x=j, y=i,s=conf_matrix[i, j], va='center', ha='center', size='large')


# Target variable and train set
Y = df[['Attack_Type']]
#print(df['Attack_Type'].unique())
X = df.drop(['Attack_Type'], axis=1)


sc = MinMaxScaler()
X = sc.fit_transform(X)


X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.33, random_state=42)

#print(X_train.shape, X_test.shape)
#print(Y_train.shape, Y_test.shape)


#GAUSSIAN NAIVE BAYES
print('\n')
print('GAUSSIAN NB')
print('----------------------------------') 
from sklearn.naive_bayes import GaussianNB
model1 = GaussianNB()
start_time = time.time()
model1.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_pred1 = model1.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------') 
Y_train_pred1 = model1.predict(X_train)
Y_train_probs1 = model1.predict_proba(X_train)
Y_test_probs1 = model1.predict_proba(X_test)
model1_train_accuracy = accuracy_score(Y_train,Y_train_pred1)
model1_train_mcc = matthews_corrcoef(Y_train,Y_train_pred1)
model1_train_f1 = f1_score(Y_train,Y_train_pred1,average = 'weighted')
model1_train_precision = precision_score(Y_train, Y_train_pred1,average='weighted')
model1_train_recall = recall_score(Y_train, Y_train_pred1, average='weighted')
model1_train_ckscore = cohen_kappa_score(Y_train, Y_train_pred1)
model1_train_logloss = log_loss(Y_train, Y_train_probs1)
#-----------------------------------------------------------------------
model1_test_accuracy = accuracy_score(Y_test,Y_test_pred1)
model1_test_mcc = matthews_corrcoef(Y_test,Y_test_pred1)
model1_test_f1 = f1_score(Y_test,Y_test_pred1,average = 'weighted')
model1_test_precision = precision_score(Y_test, Y_test_pred1,average='weighted')
model1_test_recall = recall_score(Y_test, Y_test_pred1, average='weighted')
model1_test_ckscore = cohen_kappa_score(Y_test, Y_test_pred1)
model1_test_logloss = log_loss(Y_test, Y_test_probs1)
print('- Train Accuracy : %s' % model1_train_accuracy)
print('- Train MCC : %s' % model1_train_mcc)
print('- Train F1 Score : %s' % model1_train_f1)
print('- Train Precision : %s' % model1_train_precision)
print('- Train Recall : %s' % model1_train_recall)
print('- Train Cohens Kappa Score : %s' % model1_train_ckscore)
print('- Train Log Loss : %s' % model1_train_logloss)
print('----------------------------------')
print('- Test Accuracy : %s' % model1_test_accuracy)
print('- Test MCC : %s' % model1_test_mcc)
print('- Test F1 Score : %s' % model1_test_f1)
print('- Test Precision : %s' % model1_test_precision)
print('- Test Recall : %s' % model1_test_recall)
print('- Test Cohens Kappa Score : %s' % model1_test_ckscore)
print('- Test Log Loss : %s' % model1_test_logloss)
print('----------------------------------')
print(classification_report(Y_test,Y_test_pred1,digits=20))
matrix(Y_test, Y_test_pred1)


# SUPPORT VECTOR MACHINE
print('\n')
print('SVM')
from sklearn.svm import SVC
model2 = SVC(gamma = 'scale', probability=True)
start_time = time.time()
model2.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_pred2 = model2.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------') 
Y_train_pred2 = model2.predict(X_train)
Y_train_probs2 = model2.predict_proba(X_train)
Y_test_probs2 = model2.predict_proba(X_test)
model2_train_accuracy = accuracy_score(Y_train,Y_train_pred2)
model2_train_mcc = matthews_corrcoef(Y_train,Y_train_pred2)
model2_train_f1 = f1_score(Y_train,Y_train_pred2,average = 'weighted')
model2_train_precision = precision_score(Y_train, Y_train_pred2,average='weighted')
model2_train_recall = recall_score(Y_train, Y_train_pred2, average='weighted')
model2_train_ckscore = cohen_kappa_score(Y_train, Y_train_pred2)
model2_train_logloss = log_loss(Y_train, Y_train_probs2)
#-----------------------------------------------------------------------
model2_test_accuracy = accuracy_score(Y_test,Y_test_pred2)
model2_test_mcc = matthews_corrcoef(Y_test,Y_test_pred2)
model2_test_f1 = f1_score(Y_test,Y_test_pred2,average = 'weighted')
model2_test_precision = precision_score(Y_test, Y_test_pred2,average='weighted')
model2_test_recall = recall_score(Y_test, Y_test_pred2, average='weighted')
model2_test_ckscore = cohen_kappa_score(Y_test, Y_test_pred2)
model2_test_logloss = log_loss(Y_test, Y_test_probs2)

print('- Train Accuracy : %s' % model2_train_accuracy)
print('- Train MCC : %s' % model2_train_mcc)
print('- Train F1 score : %s' % model2_train_f1)
print('- Train Precision : %s' % model2_train_precision)
print('- Train Recall : %s' % model2_train_recall)
print('- Train Cohens Kappa Score : %s' % model2_train_ckscore)
print('- Train Log Loss : %s' % model2_train_logloss)
print('----------------------------------')
print('- Test Accuracy : %s' % model2_test_accuracy)
print('- Test MCC : %s' % model2_test_mcc)
print('- Test F1 score : %s' % model2_test_f1)
print('- Test Precision : %s' % model2_test_precision)
print('- Test Recall : %s' % model2_test_recall)
print('- Test Cohens Kappa Score : %s' % model2_test_ckscore)
print('- Test Log Loss : %s' % model2_test_logloss)
print('----------------------------------')
print(classification_report(Y_test,Y_test_pred2,digits=20))
matrix(Y_test, Y_test_pred2)

"""
#Decision Tree
print('\n')
print('DT')
print('----------------------------------') 
from sklearn.tree import DecisionTreeClassifier 
model3 = DecisionTreeClassifier(criterion="entropy", max_depth = 4)
start_time = time.time()
model3.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_pred3 = model3.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------') 
Y_train_pred3 = model3.predict(X_train)
Y_train_probs3 = model3.predict_proba(X_train)
Y_test_probs3 = model3.predict_proba(X_test)

model3_train_accuracy = accuracy_score(Y_train, Y_train_pred3)
model3_train_mcc = matthews_corrcoef(Y_train, Y_train_pred3)
model3_train_f1 = f1_score(Y_train, Y_train_pred3, average='weighted')
model3_train_precision = precision_score(Y_train, Y_train_pred3,average='weighted')
model3_train_recall = recall_score(Y_train, Y_train_pred3, average='weighted')
model3_train_ckscore = cohen_kappa_score(Y_train, Y_train_pred3)
model3_train_logloss = log_loss(Y_train, Y_train_probs3)
#-----------------------------------------------------------------------
model3_test_accuracy = accuracy_score(Y_test, Y_test_pred3)
model3_test_mcc = matthews_corrcoef(Y_test, Y_test_pred3)
model3_test_f1 = f1_score(Y_test, Y_test_pred3, average='weighted')
model3_test_precision = precision_score(Y_test, Y_test_pred3,average='weighted')
model3_test_recall = recall_score(Y_test, Y_test_pred3, average='weighted')
model3_test_ckscore = cohen_kappa_score(Y_test, Y_test_pred3)
model3_test_logloss = log_loss(Y_test, Y_test_probs3)

print('- Train Accuracy : %s' % model3_train_accuracy)
print('- Train MCC : %s' % model3_train_mcc)
print('- Train F1 score: %s' % model3_train_f1)
print('- Train Precision : %s' % model3_train_precision)
print('- Train Recall : %s' % model3_train_recall)
print('- Train Cohens Kappa Score : %s' % model3_train_ckscore)
print('- Train Log Loss : %s' % model3_train_logloss)
print('----------------------------------')
print('- Test Accuracy : %s' % model3_test_accuracy)
print('- Test MCC : %s' % model3_test_mcc)
print('- Test F1 score : %s' % model3_test_f1)
print('- Test Precision : %s' % model3_test_precision)
print('- Test Recall : %s' % model3_test_recall)
print('- Test Cohens Kappa Score : %s' % model3_test_ckscore)
print('- Test Log Loss : %s' % model3_test_logloss)
print('----------------------------------')
print(classification_report(Y_test,Y_test_pred3,digits=20))
matrix(Y_test, Y_test_pred3)



# RANDOM FOREST
print('\n')
print('RF')
print('----------------------------------') 
from sklearn.ensemble import RandomForestClassifier
model4 = RandomForestClassifier(n_estimators=30)
start_time = time.time()
model4.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_pred4 = model4.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------') 
Y_train_pred4 = model4.predict(X_train)
Y_train_probs4 = model4.predict_proba(X_train)
Y_test_probs4 = model4.predict_proba(X_test)

model4_train_accuracy = accuracy_score(Y_train, Y_train_pred4)
model4_train_mcc = matthews_corrcoef(Y_train, Y_train_pred4)
model4_train_f1 = f1_score(Y_train, Y_train_pred4, average='weighted')
model4_train_precision = precision_score(Y_train, Y_train_pred4,average='weighted')
model4_train_recall = recall_score(Y_train, Y_train_pred4, average='weighted')
model4_train_ckscore = cohen_kappa_score(Y_train, Y_train_pred4)
model4_train_logloss = log_loss(Y_train, Y_train_probs4)
#-----------------------------------------------------------------------
model4_test_accuracy = accuracy_score(Y_test, Y_test_pred4)
model4_test_mcc = matthews_corrcoef(Y_test, Y_test_pred4)
model4_test_f1 = f1_score(Y_test, Y_test_pred4, average='weighted')
model4_test_precision = precision_score(Y_test, Y_test_pred4,average='weighted')
model4_test_recall = recall_score(Y_test, Y_test_pred4, average='weighted')
model4_test_ckscore = cohen_kappa_score(Y_test, Y_test_pred4)
model4_test_logloss = log_loss(Y_test, Y_test_probs4)
print('- Train Accuracy : %s' % model4_train_accuracy)
print('- Train MCC : %s' % model4_train_mcc)
print('- Train F1 score: %s' % model4_train_f1)
print('- Train Precision : %s' % model4_train_precision)
print('- Train Recall : %s' % model4_train_recall)
print('- Train Cohens Kappa Score : %s' % model4_train_ckscore)
print('- Train Log Loss : %s' % model4_train_logloss)
print('----------------------------------')
print('- Test Accuracy : %s' % model4_test_accuracy)
print('- Test MCC : %s' % model4_test_mcc)
print('- Test F1 score : %s' % model4_test_f1)
print('- Test Precision : %s' % model4_test_precision)
print('- Test Recall : %s' % model4_test_recall)
print('- Test Cohens Kappa Score : %s' % model4_test_ckscore)
print('- Test Log Loss : %s' % model4_test_logloss)
print('----------------------------------')
print(classification_report(Y_test,Y_test_pred4,digits=20))
matrix(Y_test, Y_test_pred4)


#KNN
print('\n')
print('KNN')
print('----------------------------------')
from sklearn.neighbors import KNeighborsClassifier
model5 = KNeighborsClassifier(3)
start_time = time.time()
model5.fit(X_train,Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_pred5 = model5.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------')
Y_train_pred5 = model5.predict(X_train)
Y_train_probs5 = model5.predict_proba(X_train)
Y_test_probs5 = model5.predict_proba(X_test)

model5_train_accuracy = accuracy_score(Y_train,Y_train_pred5)
model5_train_mcc = matthews_corrcoef(Y_train,Y_train_pred5)
model5_train_f1 = f1_score(Y_train,Y_train_pred5,average = 'weighted')
model5_train_precision = precision_score(Y_train, Y_train_pred5,average='weighted')
model5_train_recall = recall_score(Y_train, Y_train_pred5, average='weighted')
model5_train_ckscore = cohen_kappa_score(Y_train, Y_train_pred5)
model5_train_logloss = log_loss(Y_train, Y_train_probs5)
#-----------------------------------------------------------------------
model5_test_accuracy = accuracy_score(Y_test,Y_test_pred5)
model5_test_mcc = matthews_corrcoef(Y_test,Y_test_pred5)
model5_test_f1 = f1_score(Y_test,Y_test_pred5,average = 'weighted')
model5_test_precision = precision_score(Y_test, Y_test_pred5,average='weighted')
model5_test_recall = recall_score(Y_test, Y_test_pred5, average='weighted')
model5_test_ckscore = cohen_kappa_score(Y_test, Y_test_pred5)
model5_test_logloss = log_loss(Y_test, Y_test_probs5)
print('- Train Accuracy : %s' % model5_train_accuracy)
print('- Train MCC : %s' % model5_train_mcc)
print('- Train F1 score : %s' % model5_train_f1)
print('- Train Precision : %s' % model5_train_precision)
print('- Train Recall : %s' % model5_train_recall)
print('- Train Cohens Kappa Score : %s' % model5_train_ckscore)
print('- Train Log Loss : %s' % model5_train_logloss)
print('----------------------------------')
print('- Test Accuracy : %s' % model5_test_accuracy)
print('- Test MCC : %s' % model5_test_mcc)
print('- Test F1 score : %s' % model5_test_f1)
print('- Test Precision : %s' % model5_test_precision)
print('- Test Recall : %s' % model5_test_recall)
print('- Test Cohens Kappa Score : %s' % model5_test_ckscore)
print('- Test Log Loss : %s' % model5_test_logloss)
print('----------------------------------')
print(classification_report(Y_test,Y_test_pred5,digits=20))
matrix(Y_test, Y_test_pred5)


# LOGISTIC REGRESSION
print('\n')
print('LR')
print('----------------------------------')
from sklearn.linear_model import LogisticRegression
model6 = LogisticRegression(max_iter=1200000)
start_time = time.time()
model6.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_pred6 = model6.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------')
Y_train_pred6 = model6.predict(X_train)
Y_train_probs6 = model6.predict_proba(X_train)
Y_test_probs6 = model6.predict_proba(X_test)

model6_train_accuracy = accuracy_score(Y_train,Y_train_pred6)
model6_train_mcc = matthews_corrcoef(Y_train,Y_train_pred6)
model6_train_f1 = f1_score(Y_train,Y_train_pred6,average = 'weighted')
model6_train_precision = precision_score(Y_train, Y_train_pred6,average='weighted')
model6_train_recall = recall_score(Y_train, Y_train_pred6, average='weighted')
model6_train_ckscore = cohen_kappa_score(Y_train, Y_train_pred6)
model6_train_logloss = log_loss(Y_train, Y_train_probs6)
#-----------------------------------------------------------------------
model6_test_accuracy = accuracy_score(Y_test,Y_test_pred6)
model6_test_mcc = matthews_corrcoef(Y_test,Y_test_pred6)
model6_test_f1 = f1_score(Y_test,Y_test_pred6,average = 'weighted')
model6_test_precision = precision_score(Y_test, Y_test_pred6,average='weighted')
model6_test_recall = recall_score(Y_test, Y_test_pred6, average='weighted')
model6_test_ckscore = cohen_kappa_score(Y_test, Y_test_pred6)
model6_test_logloss = log_loss(Y_test, Y_test_probs6)
print('- Train Accuracy : %s' % model6_train_accuracy)
print('- Train MCC : %s' % model6_train_mcc)
print('- Train F1 score : %s' % model6_train_f1)
print('- Train Precision : %s' % model6_train_precision)
print('- Train Recall : %s' % model6_train_recall)
print('- Train Cohens Kappa Score : %s' % model6_train_ckscore)
print('- Train Log Loss : %s' % model6_train_logloss)
print('----------------------------------')
print('- Test Accuracy : %s' % model6_test_accuracy)
print('- Test MCC : %s' % model6_test_mcc)
print('- Test F1 score : %s' % model6_test_f1)
print('- Test Precision : %s' % model6_test_precision)
print('- Test Recall : %s' % model6_test_recall)
print('- Test Cohens Kappa Score : %s' % model6_test_ckscore)
print('- Test Log Loss : %s' % model6_test_logloss)
print('----------------------------------')
print(classification_report(Y_test,Y_test_pred6,digits=20))
matrix(Y_test, Y_test_pred6)


"""
print('\n')
print('ENSEMBLE NB-SVM')
print('----------------------------------')
from sklearn.ensemble import StackingClassifier
from sklearn.linear_model import LogisticRegression

list = [
    ('GAUSSIAN NB',model1),
    ('SVM',model2),
    #('DT',model3),
    #('RF',model4),
    #('KNN',model5),
    #('LR',model6)
    ]

stack_model1 = StackingClassifier(estimators=list, final_estimator=LogisticRegression())
start_time = time.time()
stack_model1.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_predf1 = stack_model1.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------')
Y_train_predf1 = stack_model1.predict(X_train)
Y_train_probsf1 = stack_model1.predict_proba(X_train)
Y_test_probsf1 = stack_model1.predict_proba(X_test)

# Training set model performance
stack_model1_train_accuracy = accuracy_score(Y_train, Y_train_predf1)
stack_model1_train_mcc = matthews_corrcoef(Y_train, Y_train_predf1)
stack_model1_train_f1 = f1_score(Y_train, Y_train_predf1, average='weighted') 
stack_model1_train_precision = precision_score(Y_train, Y_train_predf1,average='weighted')
stack_model1_train_recall = recall_score(Y_train, Y_train_predf1, average='weighted')
stack_model1_train_ckscore = cohen_kappa_score(Y_train, Y_train_predf1)
stack_model1_train_logloss = log_loss(Y_train, Y_train_probsf1)

# Test set model performance
stack_model1_test_accuracy = accuracy_score(Y_test, Y_test_predf1) 
stack_model1_test_mcc = matthews_corrcoef(Y_test, Y_test_predf1)
stack_model1_test_f1 = f1_score(Y_test, Y_test_predf1, average='weighted')
stack_model1_test_precision = precision_score(Y_test, Y_test_predf1,average='weighted')
stack_model1_test_recall = recall_score(Y_test, Y_test_predf1, average='weighted')
stack_model1_test_ckscore = cohen_kappa_score(Y_test, Y_test_predf1)
stack_model1_test_logloss = log_loss(Y_test, Y_test_probsf1)

print('- Train Accuracy : %s' % stack_model1_train_accuracy)
print('- Train MCC : %s' % stack_model1_train_mcc)
print('- Train F1 score : %s' % stack_model1_train_f1)
print('- Train Precision : %s' % stack_model1_train_precision)
print('- Train Recall : %s' % stack_model1_train_recall)
print('- Train Cohens Kappa Score : %s' % stack_model1_train_ckscore)
print('- Train Log Loss : %s' % stack_model1_train_logloss)
print('----------------------------------')
print('Model performance for Test set')
print('- Test Accuracy : %s' % stack_model1_test_accuracy)
print('- Test MCC : %s' % stack_model1_test_mcc)
print('- Test F1 score : %s' % stack_model1_test_f1)
print('- Test Precision : %s' % stack_model1_test_precision)
print('- Test Recall : %s' % stack_model1_test_recall)
print('- Test Cohens Kappa Score : %s' % stack_model1_test_ckscore)
print('- Test Log Loss : %s' % stack_model1_test_logloss)
print('----------------------------------')
print(classification_report(Y_test,Y_test_predf1,digits=20))
matrix(Y_test, Y_test_predf1)

"""
print('\n')
print('ENSEMBLE NB-DT-LR')
print('----------------------------------')
from sklearn.ensemble import StackingClassifier
from sklearn.linear_model import LogisticRegression

list = [
    ('GAUSSIAN NB',model1),
    #('SVM',model2),
    ('DT',model3),
    #('RF',model4),
    #('KNN',model5),
    ('LR',model6)
    ]

stack_model2 = StackingClassifier(estimators=list, final_estimator=LogisticRegression())
start_time = time.time()
stack_model2.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_predf2 = stack_model2.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------')
Y_train_predf2 = stack_model2.predict(X_train)
Y_train_probsf2 = stack_model2.predict_proba(X_train)
Y_test_probsf2 = stack_model2.predict_proba(X_test)

# Training set model performance
stack_model2_train_accuracy = accuracy_score(Y_train, Y_train_predf2)
stack_model2_train_mcc = matthews_corrcoef(Y_train, Y_train_predf2)
stack_model2_train_f1 = f1_score(Y_train, Y_train_predf2, average='weighted') 
stack_model2_train_precision = precision_score(Y_train, Y_train_predf2,average='weighted')
stack_model2_train_recall = recall_score(Y_train, Y_train_predf2, average='weighted')
stack_model2_train_ckscore = cohen_kappa_score(Y_train, Y_train_predf2)
stack_model2_train_logloss = log_loss(Y_train, Y_train_probsf2)

# Test set model performance
stack_model2_test_accuracy = accuracy_score(Y_test, Y_test_predf2) 
stack_model2_test_mcc = matthews_corrcoef(Y_test, Y_test_predf2)
stack_model2_test_f1 = f1_score(Y_test, Y_test_predf2, average='weighted')
stack_model2_test_precision = precision_score(Y_test, Y_test_predf2,average='weighted')
stack_model2_test_recall = recall_score(Y_test, Y_test_predf2, average='weighted')
stack_model2_test_ckscore = cohen_kappa_score(Y_test, Y_test_predf2)
stack_model2_test_logloss = log_loss(Y_test, Y_test_probsf2)

print('- Train Accuracy : %s' % stack_model2_train_accuracy)
print('- Train MCC : %s' % stack_model2_train_mcc)
print('- Train F1 score : %s' % stack_model2_train_f1)
print('- Train Precision : %s' % stack_model2_train_precision)
print('- Train Recall : %s' % stack_model2_train_recall)
print('- Train Cohens Kappa Score : %s' % stack_model2_train_ckscore)
print('- Train Log Loss : %s' % stack_model2_train_logloss)
print('----------------------------------')
print('Model performance for Test set')
print('- Test Accuracy : %s' % stack_model2_test_accuracy)
print('- Test MCC : %s' % stack_model2_test_mcc)
print('- Test F1 score : %s' % stack_model2_test_f1)
print('- Test Precision : %s' % stack_model2_test_precision)
print('- Test Recall : %s' % stack_model2_test_recall)
print('- Test Cohens Kappa Score : %s' % stack_model2_test_ckscore)
print('- Test Log Loss : %s' % stack_model2_test_logloss)
matrix(Y_test, Y_test_predf2)



print('\n')
print('ENSEMBLE NB-RF-LR')
print('----------------------------------')
from sklearn.ensemble import StackingClassifier
from sklearn.linear_model import LogisticRegression

list = [
    ('GAUSSIAN NB',model1),
    #('SVM',model2),
    #('DT',model3),
    ('RF',model4),
    #('KNN',model5),
    ('LR',model6)
    ]

stack_model3 = StackingClassifier(estimators=list, final_estimator=LogisticRegression())
start_time = time.time()
stack_model3.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_predf3 = stack_model3.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------')
Y_train_predf3 = stack_model3.predict(X_train)
Y_train_probsf3 = stack_model3.predict_proba(X_train)
Y_test_probsf3 = stack_model3.predict_proba(X_test)

# Training set model performance
stack_model3_train_accuracy = accuracy_score(Y_train, Y_train_predf3)
stack_model3_train_mcc = matthews_corrcoef(Y_train, Y_train_predf3)
stack_model3_train_f1 = f1_score(Y_train, Y_train_predf3, average='weighted') 
stack_model3_train_precision = precision_score(Y_train, Y_train_predf3,average='weighted')
stack_model3_train_recall = recall_score(Y_train, Y_train_predf3, average='weighted')
stack_model3_train_ckscore = cohen_kappa_score(Y_train, Y_train_predf3)
stack_model3_train_logloss = log_loss(Y_train, Y_train_probsf3)

# Test set model performance
stack_model3_test_accuracy = accuracy_score(Y_test, Y_test_predf3) 
stack_model3_test_mcc = matthews_corrcoef(Y_test, Y_test_predf3)
stack_model3_test_f1 = f1_score(Y_test, Y_test_predf3, average='weighted')
stack_model3_test_precision = precision_score(Y_test, Y_test_predf3,average='weighted')
stack_model3_test_recall = recall_score(Y_test, Y_test_predf3, average='weighted')
stack_model3_test_ckscore = cohen_kappa_score(Y_test, Y_test_predf3)
stack_model3_test_logloss = log_loss(Y_test, Y_test_probsf3)

print('- Train Accuracy : %s' % stack_model3_train_accuracy)
print('- Train MCC : %s' % stack_model3_train_mcc)
print('- Train F1 score : %s' % stack_model3_train_f1)
print('- Train Precision : %s' % stack_model3_train_precision)
print('- Train Recall : %s' % stack_model3_train_recall)
print('- Train Cohens Kappa Score : %s' % stack_model3_train_ckscore)
print('- Train Log Loss : %s' % stack_model3_train_logloss)
print('----------------------------------')
print('Model performance for Test set')
print('- Test Accuracy : %s' % stack_model3_test_accuracy)
print('- Test MCC : %s' % stack_model3_test_mcc)
print('- Test F1 score : %s' % stack_model3_test_f1)
print('- Test Precision : %s' % stack_model3_test_precision)
print('- Test Recall : %s' % stack_model3_test_recall)
print('- Test Cohens Kappa Score : %s' % stack_model3_test_ckscore)
print('- Test Log Loss : %s' % stack_model3_test_logloss)
matrix(Y_test, Y_test_predf3)


print('\n')
print('ENSEMBLE DT-RF-LR')
print('----------------------------------')
from sklearn.ensemble import StackingClassifier
from sklearn.linear_model import LogisticRegression

list = [
    #('GAUSSIAN NB',model1),
    #('SVM',model2),
    ('DT',model3),
    ('RF',model4),
    #('KNN',model5),
    ('LR',model6)
    ]

stack_model4 = StackingClassifier(estimators=list, final_estimator=LogisticRegression())
start_time = time.time()
stack_model4.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_predf4 = stack_model4.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------')
Y_train_predf4 = stack_model4.predict(X_train)
Y_train_probsf4 = stack_model4.predict_proba(X_train)
Y_test_probsf4 = stack_model4.predict_proba(X_test)

# Training set model performance
stack_model4_train_accuracy = accuracy_score(Y_train, Y_train_predf4)
stack_model4_train_mcc = matthews_corrcoef(Y_train, Y_train_predf4)
stack_model4_train_f1 = f1_score(Y_train, Y_train_predf4, average='weighted') 
stack_model4_train_precision = precision_score(Y_train, Y_train_predf4,average='weighted')
stack_model4_train_recall = recall_score(Y_train, Y_train_predf4, average='weighted')
stack_model4_train_ckscore = cohen_kappa_score(Y_train, Y_train_predf4)
stack_model4_train_logloss = log_loss(Y_train, Y_train_probsf4)

# Test set model performance
stack_model4_test_accuracy = accuracy_score(Y_test, Y_test_predf4) 
stack_model4_test_mcc = matthews_corrcoef(Y_test, Y_test_predf4)
stack_model4_test_f1 = f1_score(Y_test, Y_test_predf4, average='weighted')
stack_model4_test_precision = precision_score(Y_test, Y_test_predf4,average='weighted')
stack_model4_test_recall = recall_score(Y_test, Y_test_predf4, average='weighted')
stack_model4_test_ckscore = cohen_kappa_score(Y_test, Y_test_predf4)
stack_model4_test_logloss = log_loss(Y_test, Y_test_probsf4)

print('- Train Accuracy : %s' % stack_model4_train_accuracy)
print('- Train MCC : %s' % stack_model4_train_mcc)
print('- Train F1 score : %s' % stack_model4_train_f1)
print('- Train Precision : %s' % stack_model4_train_precision)
print('- Train Recall : %s' % stack_model4_train_recall)
print('- Train Cohens Kappa Score : %s' % stack_model4_train_ckscore)
print('- Train Log Loss : %s' % stack_model4_train_logloss)
print('----------------------------------')
print('Model performance for Test set')
print('- Test Accuracy : %s' % stack_model4_test_accuracy)
print('- Test MCC : %s' % stack_model4_test_mcc)
print('- Test F1 score : %s' % stack_model4_test_f1)
print('- Test Precision : %s' % stack_model4_test_precision)
print('- Test Recall : %s' % stack_model4_test_recall)
print('- Test Cohens Kappa Score : %s' % stack_model4_test_ckscore)
print('- Test Log Loss : %s' % stack_model4_test_logloss)
matrix(Y_test, Y_test_predf4)



print('\n')
print('ENSEMBLE NB-DT-RF-LR')
print('----------------------------------')
from sklearn.ensemble import StackingClassifier
from sklearn.linear_model import LogisticRegression

list = [
    ('GAUSSIAN NB',model1),
    #('SVM',model2),
    ('DT',model3),
    ('RF',model4),
    #('KNN',model5),
    ('LR',model6)
    ]

stack_model5 = StackingClassifier(estimators=list, final_estimator=LogisticRegression())
start_time = time.time()
stack_model5.fit(X_train, Y_train.values.ravel())
end_time = time.time()
print("- Training time : ",end_time-start_time)
start_time = time.time()
Y_test_predf5 = stack_model5.predict(X_test)
end_time = time.time()
print("- Testing time : ",end_time-start_time)
print('----------------------------------')
Y_train_predf5 = stack_model5.predict(X_train)
Y_train_probsf5 = stack_model5.predict_proba(X_train)
Y_test_probsf5 = stack_model5.predict_proba(X_test)

# Training set model performance
stack_model5_train_accuracy = accuracy_score(Y_train, Y_train_predf5)
stack_model5_train_mcc = matthews_corrcoef(Y_train, Y_train_predf5)
stack_model5_train_f1 = f1_score(Y_train, Y_train_predf5, average='weighted') 
stack_model5_train_precision = precision_score(Y_train, Y_train_predf5,average='weighted')
stack_model5_train_recall = recall_score(Y_train, Y_train_predf5, average='weighted')
stack_model5_train_ckscore = cohen_kappa_score(Y_train, Y_train_predf5)
stack_model5_train_logloss = log_loss(Y_train, Y_train_probsf5)

# Test set model performance
stack_model5_test_accuracy = accuracy_score(Y_test, Y_test_predf5) 
stack_model5_test_mcc = matthews_corrcoef(Y_test, Y_test_predf5)
stack_model5_test_f1 = f1_score(Y_test, Y_test_predf5, average='weighted')
stack_model5_test_precision = precision_score(Y_test, Y_test_predf5,average='weighted')
stack_model5_test_recall = recall_score(Y_test, Y_test_predf5, average='weighted')
stack_model5_test_ckscore = cohen_kappa_score(Y_test, Y_test_predf5)
stack_model5_test_logloss = log_loss(Y_test, Y_test_probsf5)

print('- Train Accuracy : %s' % stack_model5_train_accuracy)
print('- Train MCC : %s' % stack_model5_train_mcc)
print('- Train F1 score : %s' % stack_model5_train_f1)
print('- Train Precision : %s' % stack_model5_train_precision)
print('- Train Recall : %s' % stack_model5_train_recall)
print('- Train Cohens Kappa Score : %s' % stack_model5_train_ckscore)
print('- Train Log Loss : %s' % stack_model5_train_logloss)
print('----------------------------------')
print('Model performance for Test set')
print('- Test Accuracy : %s' % stack_model5_test_accuracy)
print('- Test MCC : %s' % stack_model5_test_mcc)
print('- Test F1 score : %s' % stack_model5_test_f1)
print('- Test Precision : %s' % stack_model5_test_precision)
print('- Test Recall : %s' % stack_model5_test_recall)
print('- Test Cohens Kappa Score : %s' % stack_model5_test_ckscore)
print('- Test Log Loss : %s' % stack_model5_test_logloss)
matrix(Y_test, Y_test_predf5)
"""

import pandas as pd
Blast = pd.read_csv('~/Desktop/Nessus Parser Script/cbres.csv')

#gives cols,rows in original CSV
print(Blast.shape)

#assigning EOL to certain CVEs | enhancement to grab CVE associated with EOL from mitre DB
EOL_CVE = ['CVE-1999-0524', 'CVE-2003-0001', 'CVE-2019-19544', 'CVE-2019-18922', 'CVE-2018-1229']
Blast.CVE.isin(EOL_CVE)
Blast_CVE = Blast[Blast.CVE.isin(EOL_CVE)]
print(Blast_CVE)
#now result show all EOL of vulns

#cmds to add column to last index withing the existing csv
Blast.insert(13,'Wolf Comment','AM - Finding')
Blast.to_csv('~/Desktop/Nessus Parser Script/cbres.csv')


#gives cols,rows for on CVE 1999-0524 and 2003-0001
#print(Blast_EOL.shape)

#risk filter TO DO
#risk = ['Critical', 'High']
#Blast.CVE.isin(risk)
#Blast_risk = Blast[Blast.CVE.isin(risk)]
#Blast_risk.CVE.unique()

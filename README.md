# EmailSyncer

## Come utilizzare lo script:
### 1. **Sincronizzazione completa:**
``` bash
ruby email_syncer.rb --email1 [email_sorgente] --password1 [password_sorgente] --host1 [host_sorgente] \
                     --email2 [email_destinazione] --password2 [password_destinazione] --host2 [host_destinazione] \
                     --sync --log [nome_file_log]
```
### 2. **Pulizia della casella di destinazione:**
``` bash
ruby email_syncer.rb --email1 [email_sorgente] --password1 [password_sorgente] --host1 [host_sorgente] \
                     --email2 [email_destinazione] --password2 [password_destinazione] --host2 [host_destinazione] \
                     --clear-dest
```
### 3. **Backup della casella sorgente:**
``` bash
ruby email_syncer.rb --email1 [email_sorgente] --password1 [password_sorgente] --host1 [host_sorgente] \
                     --backup --log [nome_file_log]
```

### 4. **Backup in formato Maildir:**
``` bash
ruby email_syncer.rb --email1 [email_sorgente] --password1 [password_sorgente] --host1 [host_sorgente] \
                     --backup --maildir --log [nome_file_log]
```

### 5. **Ripristino da backup:**
``` bash
ruby email_syncer.rb --email2 [email_destinazione] --password2 [password_destinazione] --host2 [host_destinazione] \
                     --restore [file_backup.tar.gz]
```

### 6. **Ripristino da directory Maildir:**
``` bash
ruby email_syncer.rb --email2 [email_destinazione] --password2 [password_destinazione] --host2 [host_destinazione] \
                     --restore [percorso_maildir]
```


## Caratteristiche principali:
- ✅ **Rilevamento automatico del protocollo IMAP** (testa porte 993, 143 con/senza SSL)
- ✅ **Sincronizzazione ricorsiva** di tutte le cartelle e sottocartelle
- ✅ **Monitoraggio progressi** con percentuali in tempo reale
- ✅ **Registrazione dettagliata** con opzione file di log
- ✅ **Backup compresso** in formato tar.gz con timestamp
- ✅ **Supporto formato Maildir** per backup e ripristino
- ✅ **Ripristino completo** da backup
- ✅ **Pulizia sicura** della casella di destinazione
- ✅ **Gestione errori robusta** con statistiche finali

Lo script gestisce automaticamente la connessione SSL/TLS e rileva la configurazione IMAP ottimale per entrambe le caselle di posta.

## Opzioni aggiuntive:

### Disabilitare la verifica del certificato SSL
```bash
--no-verify-ssl
```
Utile quando si lavora con server che hanno certificati autofirmati o scaduti.

### Sovrascrivere il file di log
```bash
--override-log
```
Elimina il file di log precedente prima di iniziare una nuova operazione.

## Gestione degli errori
In caso di errori di connessione, lo script fornisce una diagnostica dettagliata che include:
- Test di connettività su porte comuni
- Verifica delle credenziali
- Suggerimenti per risolvere problemi specifici
- Stato della verifica SSL

## Formato Maildir
Il formato Maildir è un formato standard per l'archiviazione di email che non utilizza file di lock ed è quindi più sicuro per l'accesso simultaneo.

### Vantaggi del formato Maildir:
- ✅ Ogni email è un file separato, facilitando la manipolazione e il backup
- ✅ Nessun rischio di corruzione del database come nei formati mbox
- ✅ Ottimo per sincronizzazioni con altri client/strumenti (offlineimap, dovecot, etc.)
- ✅ Preserva le informazioni sui flag delle email (letto, importante, etc.)
- ✅ Permette facile importazione/esportazione con altri sistemi

### Struttura del Maildir:
```
maildir_20250601_123456_username/
├── cur/         # Messaggi già visti
├── new/         # Messaggi nuovi
├── tmp/         # File temporanei
└── folders/     # Sottocartelle
    ├── Sent/
    │   ├── cur/
    │   ├── new/
    │   └── tmp/
    └── Archives/
        ├── cur/
        ├── new/
        └── tmp/
```

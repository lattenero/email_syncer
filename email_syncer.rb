#!/usr/bin/env ruby

require 'net/imap'
require 'optparse'
require 'logger'
require 'fileutils'
require 'json'
require 'zlib'
require 'rubygems/package'
require 'openssl'
require 'socket'  # Per IPSocket
require 'uri'     # Per URI.escape

class EmailSyncer
  COMMON_IMAP_PORTS = [993, 143, 587, 465]

  def initialize(options)
    @options = options
    @log_file_handle = nil
    setup_logging
    @source_imap = nil
    @dest_imap = nil
  end

  def setup_logging
    if @options[:log_file]
      # Diagnostica del filesystem
      begin
        log_dir = File.dirname(@options[:log_file])
        puts "📁 Log directory: #{log_dir} (exists: #{Dir.exist?(log_dir)}, writable: #{File.writable?(log_dir)})" 
        if File.exist?(@options[:log_file])
          puts "📄 Existing log file stats: size=#{File.size(@options[:log_file])}, permissions=#{File.stat(@options[:log_file]).mode.to_s(8)}"
        end
      rescue => e
        puts "⚠️ Filesystem diagnostics error: #{e.class} - #{e.message}"
      end

      # Rimuovi il file di log esistente se --override-log è specificato
      if @options[:override_log] && File.exist?(@options[:log_file])
        begin
          File.delete(@options[:log_file])
          puts "🗑️  Previous log file removed: #{@options[:log_file]}"
        rescue => e
          puts "⚠️ Could not delete log file: #{e.message}"
        end
      end

      # Scrittura diretta prima di aprire il file handle
      begin
        test_line = "=== DIRECT TEST WRITE at #{Time.now} ===\n"
        File.write(@options[:log_file], test_line)
        puts "✓ Direct write test successful: #{File.size(@options[:log_file])} bytes"
      rescue => e
        puts "❌ Direct write test failed: #{e.class} - #{e.message}"
      end

      # Apri il file con modalità di debug
      begin
        puts "📝 Opening log file in 'a+' mode..."
        @log_file_handle = File.open(@options[:log_file], 'a+')
        @log_file_handle.sync = true

        # Test immediato del file di log
        first_message = "=== EmailSyncer Log Started at #{Time.now} ===\n"
        @log_file_handle.write(first_message)
        @log_file_handle.flush

        # Verifica dimensione
        current_pos = @log_file_handle.pos
        puts "✓ File handle position after write: #{current_pos} bytes"

        write_log("Ruby version: #{RUBY_VERSION}")
        write_log("Command: #{$0} #{ARGV.join(' ')}")
        write_log("Log file test successful!")

        puts "📄 Log file initialized: #{@options[:log_file]}"
      rescue => e
        puts "❌ Log file handle error: #{e.class} - #{e.message}"
        @log_file_handle = nil
      end
    end
  end

  def write_log(message, level = "INFO")
    timestamp = Time.now.strftime("%Y-%m-%d %H:%M:%S")
    log_line = "[#{timestamp}] #{level}: #{message}\n"

    if @log_file_handle
      begin
        # Prova a scrivere usando due metodi diversi
        bytes_written = @log_file_handle.write(log_line)
        @log_file_handle.flush

        # Diagnostica periodica
        if rand(10) == 0  # 10% delle volte
          current_pos = @log_file_handle.pos
          file_size = File.size(@options[:log_file]) rescue 'unknown'
          puts "📊 Log diagnostics: bytes_written=#{bytes_written}, file_pos=#{current_pos}, file_size=#{file_size}" 
        end
      rescue IOError => e
        puts "❌ IOError writing to log file: #{e.message}"
        # Prova a riaprire il file
        begin
          @log_file_handle = File.open(@options[:log_file], 'a')
          @log_file_handle.sync = true
          puts "🔄 Log file handle reopened"
        rescue => reopen_error
          puts "❌ Failed to reopen log file: #{reopen_error.message}"
        end
      rescue => e
        puts "❌ Error writing to log file: #{e.class} - #{e.message}"
        puts "   Backtrace: #{e.backtrace.first(2).join(', ')}" if e.backtrace
      end
    else
      # Fallback a STDOUT se il file di log non è disponibile
      puts "[STDOUT] #{log_line.chomp}"
    end
  end

  def log_and_puts(message, level = "INFO")
    puts message
    write_log(message, level)
  end

  def detect_imap_config(host, email, password)
    log_and_puts("Detecting IMAP configuration for #{email} on #{host}")

    # SSL options based on --no-verify-ssl flag
    ssl_options = if @options[:no_verify_ssl]
                    log_and_puts("⚠️  SSL certificate verification disabled", "WARN")
                    { verify_mode: OpenSSL::SSL::VERIFY_NONE }
                  else
                    true
                  end

    # Configurazione specifica per mail.lattenero.it o il suo IP
    if host == "mail.lattenero.it" || host == "151.80.251.91"
      log_and_puts("Utilizzando configurazione ottimizzata per server mail.lattenero.it")
      configs_to_try = [
        { port: 993, ssl: ssl_options, auth_type: :login },  # Prima configurazione da tentare
        { port: 993, ssl: ssl_options, auth_type: :plain },  # Seconda configurazione
        { port: 993, ssl: true },                          # Terza: prova SSL standard
        { port: 993, ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE } } # Quarta: SSL senza verifica
      ]
    else
      # Configurazioni standard per altri server
      configs_to_try = [
        { port: 993, ssl: ssl_options },
        { port: 143, ssl: false, starttls: true },  # STARTTLS sulla porta 143
        { port: 143, ssl: false },                # Plain sulla porta 143
        { port: 143, ssl: ssl_options },          # SSL diretto sulla porta 143 (raro)
        { port: 465, ssl: ssl_options },
        { port: 587, ssl: false, starttls: true }, # STARTTLS sulla porta 587 (comune per SMTP)
        { port: 587, ssl: false },
        { port: 587, ssl: ssl_options }
      ]
    end

    log_and_puts("Testing #{configs_to_try.length} different IMAP configurations...")

    configs_to_try.each_with_index do |config, index|
      begin
        ssl_desc = case config[:ssl]
                   when false
                     "SSL: disabled"
                   when true
                     "SSL: enabled"
                   when Hash
                     "SSL: enabled (certificate not verified)"
                   else
                     "SSL: #{config[:ssl]}"
                   end

        log_and_puts("#{index + 1}/#{configs_to_try.length} - Trying connection on port #{config[:port]} (#{ssl_desc})")

        # Try connection with longer timeout
        imap = Net::IMAP.new(host, port: config[:port], ssl: config[:ssl], open_timeout: 15)
        log_and_puts("✓ TCP connection successful on port #{config[:port]}")

        # Attiva STARTTLS se configurato
        if config[:starttls] && !config[:ssl]
          begin
            log_and_puts("Trying STARTTLS on port #{config[:port]}...")
            imap.starttls(verify_mode: OpenSSL::SSL::VERIFY_NONE) if @options[:no_verify_ssl]
            imap.starttls unless @options[:no_verify_ssl]
            log_and_puts("✓ STARTTLS attivato con successo")
          rescue => e
            log_and_puts("✗ STARTTLS fallito: #{e.message}", "WARN")
            # Continuiamo comunque, potrebbe funzionare senza STARTTLS
          end
        end

        # Try login with full email using different methods
        auth_methods = config[:auth_type] ? [config[:auth_type]] : [:login, :authenticate_plain]
        auth_success = false

        # Per mail.lattenero.it, prova prima con solo username
        if host == "mail.lattenero.it" || host == "151.80.251.91"
          username = email.split('@')[0]
          log_and_puts("Mail.lattenero.it: trying with username only first: #{username}")

          # Variazioni di username da provare
          username_variants = [username]

          # Prova anche con user@domain.it
          username_variants << email if email.include?('@')

          # Prova anche con formati alternativi tipici per server di posta
          domain = email.split('@')[1] if email.include?('@')
          if domain
            username_variants << "#{username}@#{domain}"
            username_variants << "#{username}%#{domain}"
          end

          username_variants.uniq.each do |variant|
            break if auth_success
            log_and_puts("Trying username variant: #{variant}")

            auth_methods.each do |method|
              break if auth_success
              begin
                if method == :login
                  log_and_puts("Attempting standard LOGIN with: #{variant}")
                  imap.login(variant, password)
                else
                  log_and_puts("Attempting AUTHENTICATE PLAIN with: #{variant}")
                  imap.authenticate('PLAIN', variant, password)
                end
                log_and_puts("✓ Login successful with #{variant} (method: #{method})")
                auth_success = true
              rescue => e
                log_and_puts("✗ Login with #{variant} failed: #{e.message}", "WARN")
              end
            end
          end
        end

        # Se non abbiamo avuto successo con username, proviamo con email completa
        unless auth_success
          auth_methods.each do |method|
            break if auth_success

            # Prova con email completa
            begin
              if method == :login
                log_and_puts("Attempting standard LOGIN with full email: #{email}")
                imap.login(email, password)
              else
                log_and_puts("Attempting AUTHENTICATE PLAIN with full email: #{email}")
                imap.authenticate('PLAIN', email, password)
              end
              log_and_puts("✓ Login successful with full email (method: #{method})")
              auth_success = true
            rescue Net::IMAP::NoResponseError, Net::IMAP::BadResponseError, Net::IMAP::ResponseError => e
              log_and_puts("✗ #{method} failed with full email: #{e.message}", "WARN")
            rescue => e
              log_and_puts("✗ Unexpected error with #{method}: #{e.class} - #{e.message}", "WARN")
            end
          end
        end

        # Se l'autenticazione è fallita con l'email completa, prova con username
        unless auth_success
          username = email.split('@')[0]

          auth_methods.each do |method|
            break if auth_success

            begin
              if method == :login
                log_and_puts("Attempting standard LOGIN with username: #{username}")
                imap.login(username, password)
              else
                log_and_puts("Attempting AUTHENTICATE PLAIN with username: #{username}")
                imap.authenticate('PLAIN', username, password)
              end
              log_and_puts("✓ Login successful with username (method: #{method})")
              auth_success = true
            rescue Net::IMAP::NoResponseError, Net::IMAP::BadResponseError, Net::IMAP::ResponseError => e
              log_and_puts("✗ #{method} failed with username: #{e.message}", "WARN")
            rescue => e
              log_and_puts("✗ Unexpected error with #{method}: #{e.class} - #{e.message}", "WARN")
            end
          end
        end

        # Se nessun metodo ha funzionato, solleva un errore
        unless auth_success
          raise Net::IMAP::NoResponseError.new("All authentication methods failed")
        end

        log_and_puts("✓ Configuration found: port #{config[:port]}, #{ssl_desc}")
        return { imap: imap, config: config }

      rescue Net::IMAP::NoResponseError => e
        log_and_puts("✗ Authentication error on port #{config[:port]}: #{e.message}", "WARN")
        log_and_puts("   This could indicate wrong credentials or server requiring special configurations", "WARN")
        begin
          imap&.disconnect
        rescue
        end
      rescue SocketError => e
        log_and_puts("✗ Network error on port #{config[:port]}: #{e.message}", "WARN")
        log_and_puts("   The server might not be reachable on this port", "WARN")
      rescue Errno::ECONNREFUSED => e
        log_and_puts("✗ Connection refused on port #{config[:port]}: #{e.message}", "WARN")
        log_and_puts("   The IMAP service might not be active on this port", "WARN")
      rescue Timeout::Error => e
        log_and_puts("✗ Timeout on port #{config[:port]}: #{e.message}", "WARN")
        log_and_puts("   The server might be slow or not responding", "WARN")
      rescue OpenSSL::SSL::SSLError => e
        log_and_puts("✗ SSL error on port #{config[:port]}: #{e.message}", "WARN")
        log_and_puts("   Problem with SSL certificate or encryption configuration", "WARN")
        if !@options[:no_verify_ssl]
          log_and_puts("   💡 Try adding --no-verify-ssl to ignore certificates", "WARN")
        end
      rescue => e
        log_and_puts("✗ Generic error on port #{config[:port]}: #{e.class} - #{e.message}", "WARN")
        log_and_puts("   Backtrace: #{e.backtrace.first(3).join(', ')}", "WARN")
        begin
          imap&.disconnect
        rescue
        end
      end
    end

    # Detailed diagnostics
    log_and_puts("=" * 60, "ERROR")
    log_and_puts("DIAGNOSTICS: All connection attempts failed for #{email}", "ERROR")
    log_and_puts("Host tested: #{host}", "ERROR")
    log_and_puts("IP address: #{IPSocket.getaddress(host) rescue 'Unable to resolve'}", "ERROR")
    log_and_puts("SSL verification: #{@options[:no_verify_ssl] ? 'DISABLED' : 'ENABLED'}", "ERROR")

    # Se è mail.lattenero.it, aggiungi info specifiche
    if host == "mail.lattenero.it" || host == "151.80.251.91" || email.end_with?("@lattenero.it")
      log_and_puts("LATTENERO SPECIFICS:", "ERROR")
      log_and_puts("- Questo server potrebbe richiedere autenticazione con solo username (senza @lattenero.it)", "ERROR")
      log_and_puts("- Potrebbe anche richiedere un prefisso per lo username o una password app specifica", "ERROR")
      log_and_puts("- Per account specifici, potrebbe essere necessario abilitare IMAP nelle impostazioni account", "ERROR")
    end

    # Test basic connectivity
    [143, 993, 587, 465, 25, 110].each do |test_port|
      begin
        socket = TCPSocket.new(host, test_port)
        banner = socket.gets rescue nil
        log_and_puts("Port #{test_port} open: #{banner ? 'Yes (banner: ' + banner.strip + ')' : 'Yes (no banner)'}", "ERROR")
        socket.close rescue nil
      rescue => e
        log_and_puts("Port #{test_port} closed or filtered: #{e.message.split(' ').first}", "ERROR")
      end
    end
    log_and_puts("=" * 60, "ERROR")
    log_and_puts("POSSIBLE CAUSES:", "ERROR")
    log_and_puts("1. 🔐 CREDENTIALS: Wrong email or password", "ERROR")
    log_and_puts("2. 🏠 HOST: #{host} might not be the correct IMAP server", "ERROR")
    log_and_puts("3. 🔒 SECURITY: Might need an 'app password'", "ERROR")
    log_and_puts("4. ⚙️  CONFIGURATION: IMAP access might be disabled", "ERROR")
    log_and_puts("5. 🛡️  FIREWALL: Ports blocked by firewall or provider", "ERROR")
    log_and_puts("6. 🔐 SSL: SSL certificate issues", "ERROR")
    log_and_puts("=" * 60, "ERROR")
    log_and_puts("SUGGESTIONS:", "ERROR")
    log_and_puts("- Verify credentials in email client", "ERROR")
    log_and_puts("- Check if you need to enable 'Less secure app access'", "ERROR")
    log_and_puts("- Try with an app password if using 2FA", "ERROR")
    log_and_puts("- Verify that IMAP is enabled in the account", "ERROR")
    log_and_puts("- For SSL issues, try --no-verify-ssl", "ERROR") unless @options[:no_verify_ssl]
    log_and_puts("- Try with IP address instead of hostname", "ERROR")
    log_and_puts("=" * 60, "ERROR")

    return nil # Return nil instead of raising immediately
  end

  def connect_to_mailboxes
    log_and_puts("Starting mailbox connection process...")

    # Se stiamo usando mail.lattenero.it ma abbiamo inserito l'IP, correggi l'host
    if (@options[:host1] == "151.80.251.91" || @options[:host2] == "151.80.251.91") && 
       ((@options[:email1] && @options[:email1].end_with?("@lattenero.it")) || 
        (@options[:email2] && @options[:email2].end_with?("@lattenero.it")))
      log_and_puts("🔄 Nota: L'indirizzo IP 151.80.251.91 appartiene a mail.lattenero.it", "INFO")
      log_and_puts("   Consigliato usare il nome host mail.lattenero.it in futuro", "INFO")
    end

    puts "🔍 Testing source mailbox connection..."
    source_result = detect_imap_config(@options[:host1], @options[:email1], @options[:password1])
    if source_result.nil?
      log_and_puts("❌ Failed to connect to source mailbox: #{@options[:email1]}", "ERROR")
      return false
    end
    @source_imap = source_result[:imap]
    log_and_puts("✓ Connected to source mailbox: #{@options[:email1]}")
    puts "✅ Source mailbox connected successfully"

    puts "🔍 Testing destination mailbox connection..."
    dest_result = detect_imap_config(@options[:host2], @options[:email2], @options[:password2])
    if dest_result.nil?
      log_and_puts("❌ Failed to connect to destination mailbox: #{@options[:email2]}", "ERROR")
      return false
    end
    @dest_imap = dest_result[:imap]
    log_and_puts("✓ Connected to destination mailbox: #{@options[:email2]}")
    puts "✅ Destination mailbox connected successfully"

    return true
  end

  def get_folder_list(imap)
    folders = []
    imap.list("", "*").each do |folder|
      folders << folder.name
    end
    folders
  end

  def sync_folder(folder_name, stats)
    write_log("Synchronizing folder: #{folder_name}")

    begin
      @source_imap.select(folder_name)
      source_messages = @source_imap.search(["ALL"])

      # Create destination folder if it doesn't exist
      begin
        @dest_imap.create(folder_name)
      rescue Net::IMAP::NoResponseError
        # Folder already exists
      end

      @dest_imap.select(folder_name)
      dest_messages = @dest_imap.search(["ALL"])

      messages_to_copy = source_messages.length - dest_messages.length

      if messages_to_copy > 0
        write_log("Copying #{messages_to_copy} messages...")

        source_messages.each_with_index do |msg_id, index|
          begin
            msg_data = @source_imap.fetch(msg_id, "RFC822")[0].attr["RFC822"]
            @dest_imap.append(folder_name, msg_data)

            stats[:copied_messages] += 1

            # Show progress every 10 messages
            if (index + 1) % 10 == 0
              progress = ((index + 1).to_f / source_messages.length * 100).round(2)
              puts "Folder #{folder_name} progress: #{progress}%"
            end

          rescue => e
            write_log("Error copying message #{msg_id}: #{e.message}", "ERROR")
            stats[:failed_messages] += 1
          end
        end
      end

      stats[:synced_folders] += 1
      write_log("✓ Folder #{folder_name} synchronized")

    rescue => e
      write_log("Error synchronizing folder #{folder_name}: #{e.message}", "ERROR")
      stats[:failed_folders] += 1
    end
  end

  def sync_mailboxes
    unless connect_to_mailboxes
      puts "\n❌ Connection failed. Check the log file for detailed diagnostics."
      log_and_puts("Sync operation failed due to connection errors", "ERROR")
      return false
    end

    write_log("Starting synchronization...")

    source_folders = get_folder_list(@source_imap)
    total_folders = source_folders.length
    write_log("Found #{total_folders} folders to synchronize")

    stats = {
      synced_folders: 0,
      failed_folders: 0,
      copied_messages: 0,
      failed_messages: 0
    }

    source_folders.each_with_index do |folder, index|
      sync_folder(folder, stats)

      # Show total progress
      progress = ((index + 1).to_f / total_folders * 100).round(2)
      puts "Total progress: #{progress}% (#{index + 1}/#{total_folders} folders)"
    end

    write_log("Synchronization completed!")
    write_log("Statistics:")
    write_log("- Synchronized folders: #{stats[:synced_folders]}/#{total_folders}")
    write_log("- Copied messages: #{stats[:copied_messages]}")
    write_log("- Failed messages: #{stats[:failed_messages]}")

    puts "\n📊 Final results:"
    puts "✓ Synchronized folders: #{stats[:synced_folders]}/#{total_folders}"
    puts "✓ Copied messages: #{stats[:copied_messages]}"
    puts "⚠️  Failed messages: #{stats[:failed_messages]}" if stats[:failed_messages] > 0

    return true
  end

  def clear_destination
    unless connect_to_mailboxes
      puts "\n❌ Connection failed. Check the log file for detailed diagnostics."
      return false
    end

    write_log("Clearing destination mailbox content...")

    folders = get_folder_list(@dest_imap)

    folders.each do |folder|
      begin
        @dest_imap.select(folder)
        messages = @dest_imap.search(["ALL"])

        if messages.any?
          write_log("Deleting #{messages.length} messages from folder #{folder}")
          @dest_imap.store(messages, "+FLAGS", [:Deleted])
          @dest_imap.expunge
        end

        # Don't delete system folders
        unless ['INBOX', 'Sent', 'Drafts', 'Trash'].include?(folder)
          begin
            @dest_imap.delete(folder)
            write_log("Folder #{folder} deleted")
          rescue
            write_log("Unable to delete folder #{folder}", "WARN")
          end
        end

      rescue => e
        write_log("Error deleting folder #{folder}: #{e.message}", "ERROR")
      end
    end

    write_log("✓ Destination mailbox cleared")
    puts "✓ Destination mailbox completely cleared"
    return true
  end

  def backup_source_mailbox
    puts "🔍 Testing source mailbox connection..."
    source_result = detect_imap_config(@options[:host1], @options[:email1], @options[:password1])
    if source_result.nil?
      puts "❌ Failed to connect to source mailbox: #{@options[:email1]}"
      return false
    end
    @source_imap = source_result[:imap]
    puts "✅ Source mailbox connected successfully"

    date_str = Time.now.strftime("%Y%m%d_%H%M%S")
    mailbox_name = @options[:email1].split('@')[0]

    # Determina se utilizzare Maildir o file tar.gz in base all'opzione
    if @options[:maildir]
      backup_dir = "maildir_#{date_str}_#{mailbox_name}"
      write_log("Creating Maildir backup of source mailbox...")
      write_log("Backup directory: #{backup_dir}")

      # Struttura Maildir
      FileUtils.mkdir_p(File.join(backup_dir, "cur"))
      FileUtils.mkdir_p(File.join(backup_dir, "new"))
      FileUtils.mkdir_p(File.join(backup_dir, "tmp"))
    else
      backup_filename = "#{date_str}_#{mailbox_name}.tar.gz"
      write_log("Creating backup of source mailbox...")
      write_log("Backup file: #{backup_filename}")
    end

    # Temporary directory for email files
    temp_dir = "temp_backup_#{date_str}"
    FileUtils.mkdir_p(temp_dir)

    begin
      folders = get_folder_list(@source_imap)

      folders.each_with_index do |folder, index|
        write_log("Backing up folder: #{folder}")

        if @options[:maildir]
          # Crea sottocartella nella struttura Maildir
          folder_dir = File.join(backup_dir, "folders", folder.gsub('/', '_'))
          FileUtils.mkdir_p(File.join(folder_dir, "cur"))
          FileUtils.mkdir_p(File.join(folder_dir, "new"))
          FileUtils.mkdir_p(File.join(folder_dir, "tmp"))
        else
          folder_dir = File.join(temp_dir, folder.gsub('/', '_'))
          FileUtils.mkdir_p(folder_dir)
        end

        @source_imap.select(folder)
        messages = @source_imap.search(["ALL"])

        messages.each_with_index do |msg_id, msg_index|
          begin
            # Ottieni dati e flag del messaggio
            msg_fetch = @source_imap.fetch(msg_id, ["RFC822", "FLAGS", "INTERNALDATE"])[0]
            msg_data = msg_fetch.attr["RFC822"]
            msg_flags = msg_fetch.attr["FLAGS"]
            msg_date = msg_fetch.attr["INTERNALDATE"]

            if @options[:maildir]
              # Formato Maildir: genera un nome file unico
              unique_id = "#{Time.now.to_i}.#{Process.pid}.#{mailbox_name}"
              flag_str = maildir_flags_from_imap(msg_flags)

              # Posiziona nella cartella 'cur' perché sono messaggi esistenti
              msg_filename = File.join(folder_dir, "cur", "#{unique_id}:2,#{flag_str}")
              File.write(msg_filename, msg_data)

              # Aggiorna i timestamp per preservare la data originale
              File.utime(msg_date, msg_date, msg_filename) rescue nil
            else
              msg_filename = File.join(folder_dir, "#{msg_id}.eml")
              File.write(msg_filename, msg_data)
            end

            if (msg_index + 1) % 50 == 0
              progress = ((msg_index + 1).to_f / messages.length * 100).round(2)
              puts "Backup folder #{folder}: #{progress}%"
            end

          rescue => e
            write_log("Error during backup of message #{msg_id}: #{e.message}", "ERROR")
          end
        end

        # Salva i metadati della cartella
        metadata = {
          folder_name: folder,
          message_count: messages.length,
          backup_date: Time.now.iso8601
        }

        if @options[:maildir]
          File.write(File.join(folder_dir, "metadata.json"), JSON.pretty_generate(metadata))
        else
          File.write(File.join(folder_dir, "metadata.json"), JSON.pretty_generate(metadata))
        end

        progress = ((index + 1).to_f / folders.length * 100).round(2)
        puts "Backup progress: #{progress}% (#{index + 1}/#{folders.length} folders)"
      end

      if @options[:maildir]
        # Per Maildir, aggiungi un file con informazioni generali sul backup
        info = {
          source_email: @options[:email1],
          host: @options[:host1],
          backup_date: Time.now.iso8601,
          total_folders: folders.length,
          backup_type: "maildir",
          format_version: "1.0"
        }
        File.write(File.join(backup_dir, "backup_info.json"), JSON.pretty_generate(info))

        write_log("✓ Maildir backup completed: #{backup_dir}")
        puts "✓ Maildir backup created successfully: #{backup_dir}"
      else
        # Create tar.gz archive
        write_log("Creating compressed archive...")

        File.open(backup_filename, 'wb') do |file|
          Zlib::GzipWriter.wrap(file) do |gz|
            Gem::Package::TarWriter.new(gz) do |tar|
              add_directory_to_tar(tar, temp_dir, temp_dir)
            end
          end
        end

        write_log("✓ Backup completed: #{backup_filename}")
        puts "✓ Backup created successfully: #{backup_filename}"
      end

    ensure
      FileUtils.rm_rf(temp_dir) if Dir.exist?(temp_dir)
    end

    return true
  end

      def restore_from_backup(backup_source)
    # Controlla se è un file di backup (tar.gz) o una directory Maildir
    is_maildir = File.directory?(backup_source) && 
                Dir.exist?(File.join(backup_source, "cur")) && 
                Dir.exist?(File.join(backup_source, "new"))

    is_file = File.file?(backup_source) && backup_source.end_with?(".tar.gz")

    unless is_maildir || is_file
      raise "Invalid backup source: #{backup_source}. Must be a .tar.gz file or Maildir directory."
    end

    unless connect_to_mailboxes
      puts "\n❌ Connection failed. Check the log file for detailed diagnostics."
      return false
    end

    write_log("Restoring from backup: #{backup_source}")

    # Temporary directory to extract backup or process Maildir
    temp_dir = "temp_restore_#{Time.now.strftime('%Y%m%d_%H%M%S')}"

    begin
      if is_file
        # Extract archive
        write_log("Extracting archive...")
        File.open(backup_source, 'rb') do |file|
          Zlib::GzipReader.wrap(file) do |gz|
            Gem::Package::TarReader.new(gz) do |tar|
              tar.each do |entry|
                next unless entry.file?

                file_path = File.join(temp_dir, entry.full_name)
                FileUtils.mkdir_p(File.dirname(file_path))

                File.open(file_path, 'wb') do |f|
                  f.write(entry.read)
                end
              end
            end
          end
        end
      else
        # È un Maildir, verifica se ha una struttura folders/ o è un backup di una singola casella
        if Dir.exist?(File.join(backup_source, "folders"))
          # Copia la struttura folders in temp_dir
          FileUtils.cp_r(File.join(backup_source, "folders"), temp_dir)
        else
          # È un Maildir semplice, creando una cartella INBOX nel temp_dir
          FileUtils.mkdir_p(File.join(temp_dir, "INBOX"))
          # Copia tutti i messaggi da cur/ e new/ alla directory INBOX
          Dir.glob(File.join(backup_source, "cur", "*")).each do |mail_file|
            FileUtils.cp(mail_file, File.join(temp_dir, "INBOX", File.basename(mail_file)))
          end
          Dir.glob(File.join(backup_source, "new", "*")).each do |mail_file|
            FileUtils.cp(mail_file, File.join(temp_dir, "INBOX", File.basename(mail_file)))
          end
        end
      end

      # Restore folders and messages
      Dir.glob(File.join(temp_dir, "*")).each do |folder_path|
        next unless File.directory?(folder_path)

        # Salta le directory speciali di Maildir se presenti
        next if ["cur", "new", "tmp"].include?(File.basename(folder_path))

        folder_name = File.basename(folder_path).gsub('_', '/')

        # Read metadata if it exists
        metadata_file = File.join(folder_path, "metadata.json")
        if File.exist?(metadata_file)
          metadata = JSON.parse(File.read(metadata_file))
          folder_name = metadata['folder_name']
        end

        write_log("Restoring folder: #{folder_name}")

        # Create folder
        begin
          @dest_imap.create(folder_name)
        rescue Net::IMAP::NoResponseError
          # Folder already exists
        end

        @dest_imap.select(folder_name)

        # Controlla se è una struttura Maildir
        if Dir.exist?(File.join(folder_path, "cur")) || Dir.exist?(File.join(folder_path, "new"))
          # Ottieni messaggi da cur/ e new/
          email_files = []
          email_files += Dir.glob(File.join(folder_path, "cur", "*")) if Dir.exist?(File.join(folder_path, "cur"))
          email_files += Dir.glob(File.join(folder_path, "new", "*")) if Dir.exist?(File.join(folder_path, "new"))
        else
          # Struttura classica con file .eml
          email_files = Dir.glob(File.join(folder_path, "*.eml"))
        end

        email_files.each_with_index do |email_file, index|
          begin
            msg_data = File.read(email_file)

            # Estrai flags se il file è in formato Maildir
            flags = []
            if File.basename(File.dirname(email_file)) == "cur" || File.basename(File.dirname(email_file)) == "new"
              # Analizza il nome del file per estrarre i flag Maildir
              if File.basename(email_file).include?(":2,")
                flag_part = File.basename(email_file).split(":2,")[1]
                # Converti i flag Maildir in flag IMAP
                flags << :Seen if flag_part.include?("S")
                flags << :Flagged if flag_part.include?("F")
                flags << :Answered if flag_part.include?("R")
                flags << :Draft if flag_part.include?("D")
                flags << :Deleted if flag_part.include?("T")
              end
            end

            # Aggiungi il messaggio con i flag appropriati
            if flags.empty?
              @dest_imap.append(folder_name, msg_data)
            else
              @dest_imap.append(folder_name, msg_data, flags)
            end

            if (index + 1) % 10 == 0
              progress = ((index + 1).to_f / email_files.length * 100).round(2)
              puts "Restoring folder #{folder_name}: #{progress}%"
            end

          rescue => e
            write_log("Error restoring message from #{email_file}: #{e.message}", "ERROR")
          end
        end

        write_log("✓ Folder #{folder_name} restored (#{email_files.length} messages)")
      end

      write_log("✓ Restore completed")
      puts "✓ Restore completed successfully"

    ensure
      FileUtils.rm_rf(temp_dir) if Dir.exist?(temp_dir)
    end

    return true
  end

  def disconnect
    begin
      @source_imap&.disconnect
      @dest_imap&.disconnect
    rescue
    end

    # Chiudi il file di log
    if @log_file_handle
      write_log("=== EmailSyncer Log Ended at #{Time.now} ===")
      @log_file_handle.close
      @log_file_handle = nil

      # Verifica contenuti finali del log
      if @options[:log_file]
        begin
          # Ottieni percorso assoluto
          absolute_path = File.expand_path(@options[:log_file])
          puts "📋 Log file absolute path: #{absolute_path}"

          if File.exist?(absolute_path)
            size = File.size(absolute_path)
            puts "📄 Final log file size: #{size} bytes"

            # Mostra le prime righe del log
            if size > 0
              puts "\n📃 Prime 3 righe del log:"
              File.open(absolute_path, 'r') do |f|
                3.times do
                  line = f.gets
                  break unless line
                  puts "   #{line.chomp}"
                end
              end
              puts "   [...]\n"

              # Crea una copia di backup che possiamo sicuramente leggere
              backup_log = "#{absolute_path}.backup"
              FileUtils.cp(absolute_path, backup_log)
              puts "💾 File di log copiato in: #{backup_log}"
              puts "   Per visualizzare il contenuto esegui: cat #{backup_log}"
            else
              puts "⚠️ Il file di log esiste ma è vuoto!"
            end
          else
            puts "❌ Il file di log non esiste al percorso: #{absolute_path}"

            # Cerca nelle directory vicine
            puts "🔍 Ricerca del file in directory vicine..."
            log_name = File.basename(@options[:log_file])
            ['..', '../..', '.', './logs', '/tmp'].each do |dir|
              check_path = File.expand_path(File.join(dir, log_name))
              if File.exist?(check_path)
                puts "✅ Trovato file in: #{check_path} (#{File.size(check_path)} bytes)"
              end
            end
          end

          # Prova un metodo di scrittura alternativo per debugging
          emergency_log = "#{@options[:log_file]}.emergency"
          puts "⚠️ Creating emergency log file: #{emergency_log}"
          File.open(emergency_log, 'w') do |f|
            f.puts("=== EMERGENCY LOG at #{Time.now} ===")
            f.puts("Original log file path: #{absolute_path}")
            f.puts("Original log exists: #{File.exist?(absolute_path)}")
            f.puts("Original log size: #{File.size(absolute_path) rescue 'N/A'}")
            f.puts("Ruby version: #{RUBY_VERSION}")
            f.puts("Ruby platform: #{RUBY_PLATFORM}")
            f.puts("Command: #{$0} #{ARGV.join(' ')}")
            f.puts("Working directory: #{Dir.pwd}")
          end
          puts "✓ Emergency log created: #{emergency_log} (size: #{File.size(emergency_log)} bytes)"
        rescue => e
          puts "❌ Error during log file verification: #{e.class} - #{e.message}"
        end
      end
    end
  end

  private

  # Converte i flag IMAP in flag Maildir
  def maildir_flags_from_imap(imap_flags)
    maildir_flags = ""
    # Flag Maildir standard: D (draft), F (flagged), R (replied), S (seen), T (trashed)
    maildir_flags += "D" if imap_flags.include?(:Draft)
    maildir_flags += "F" if imap_flags.include?(:Flagged)
    maildir_flags += "R" if imap_flags.include?(:Answered)
    maildir_flags += "S" if imap_flags.include?(:Seen)
    maildir_flags += "T" if imap_flags.include?(:Deleted)
    # Ordina alfabeticamente come richiesto dalla specifica Maildir
    maildir_flags.chars.sort.join
  end

  def add_directory_to_tar(tar, source_dir, base_dir)
    Dir.glob(File.join(source_dir, "**/*"), File::FNM_DOTMATCH).each do |file|
      next if File.basename(file) == '.' || File.basename(file) == '..'

      relative_path = file.sub("#{base_dir}/", "")

      if File.directory?(file)
        tar.mkdir(relative_path, 0755)
      else
        tar.add_file(relative_path, 0644) do |io|
          io.write(File.read(file))
        end
      end
    end
  end
end

# Command line arguments parsing
options = {}

OptionParser.new do |opts|
  opts.banner = "Usage: ruby email_syncer.rb [options]"

  opts.on("--email1 EMAIL", "Source mailbox email") do |email|
    options[:email1] = email
  end

  opts.on("--password1 PASSWORD", "Source mailbox password") do |password|
    options[:password1] = password
  end

  opts.on("--host1 HOST", "Source IMAP host (can be hostname or IP)") do |host|
    options[:host1] = host
  end

  opts.on("--email2 EMAIL", "Destination mailbox email") do |email|
    options[:email2] = email
  end

  opts.on("--password2 PASSWORD", "Destination mailbox password") do |password|
    options[:password2] = password
  end

  opts.on("--host2 HOST", "Destination IMAP host (can be hostname or IP)") do |host|
    options[:host2] = host
  end

  opts.on("--no-verify-ssl", "Disable SSL certificate verification") do
    options[:no_verify_ssl] = true
  end

  opts.on("--log FILE", "Log file (optional)") do |log_file|
    options[:log_file] = log_file
  end

  opts.on("--override-log", "Remove previous log file if it exists") do
    options[:override_log] = true
  end

  opts.on("--maildir", "Use Maildir format for backup and restore") do
    options[:maildir] = true
  end

  opts.on("--maildir-path PATH", "Path to Maildir directory (for backup or restore)") do |path|
    options[:maildir_path] = path
  end

  opts.on("--sync", "Synchronize from source to destination") do
    options[:action] = :sync
  end

  opts.on("--clear-dest", "Clear only the destination mailbox") do
    options[:action] = :clear_dest
  end

  opts.on("--backup", "Create backup of source mailbox") do
    options[:action] = :backup
  end

  opts.on("--restore FILE", "Restore from backup file") do |backup_file|
    options[:action] = :restore
    options[:backup_file] = backup_file
  end

  opts.on_tail("-h", "--help", "Show this help message") do
    puts opts
    puts "\nUsage examples:"
    puts "  # Synchronization with SSL verification disabled and fresh log"
    puts "  ruby email_syncer.rb --email1 user@example.com --password1 pass1 --host1 mail.example.com \\"
    puts "                       --email2 user@dest.com --password2 pass2 --host2 10.0.0.1 \\"
    puts "                       --no-verify-ssl --sync --log sync.log --override-log"
    puts ""
    puts "  # Backup with unverified certificates and clean log"
    puts "  ruby email_syncer.rb --email1 user@example.com --password1 pass1 --host1 192.168.1.100 \\"
    puts "                       --no-verify-ssl --backup --log backup.log --override-log"
    exit
  end
end.parse!

# Basic parameter validation
required_params = [:email1, :password1, :host1]
unless options[:action] == :restore
  required_params += [:email2, :password2, :host2]
end

missing_params = required_params.select { |param| options[param].nil? }

if missing_params.any? || options[:action].nil?
  puts "❌ Missing parameters: #{missing_params.join(', ')}" if missing_params.any?
  puts "❌ Missing action. Use --sync, --clear-dest, --backup, or --restore FILE" unless options[:action]
  puts "\nUse --help to see all available options"
  exit 1
end

# Show SSL information if disabled
if options[:no_verify_ssl]
  puts "⚠️  WARNING: SSL certificate verification disabled"
  puts "   Less secure connections but compatible with self-signed certificates"
  puts ""
end

# Execute requested action
begin
  syncer = EmailSyncer.new(options)
  success = false

  case options[:action]
  when :sync
    puts "🔄 Starting email synchronization..."
    success = syncer.sync_mailboxes
  when :clear_dest
    puts "🗑️  Clearing destination mailbox..."
    success = syncer.clear_destination
  when :backup
    puts "💾 Creating source mailbox backup..."
    success = syncer.backup_source_mailbox
  when :restore
    puts "📥 Restoring from backup..."
    success = syncer.restore_from_backup(options[:backup_file])
  end

  if success
    puts "\n✅ Operation completed successfully!"
  else
    puts "\n❌ Operation failed. Check the log file for details."
    if options[:log_file] && File.exist?(options[:log_file])
      puts "📄 Log file: #{options[:log_file]}"
    end
    exit 1
  end

ensure
  syncer&.disconnect
end

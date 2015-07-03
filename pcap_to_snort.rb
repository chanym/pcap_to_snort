#!/usr/bin/ruby

def begin_analysis(pcap_file, intel_file = nil)
		intel_feed = []
		http_data = []
		https_data = []
		dns_data = []

    if intel_file
      puts "Reading intelligent feeds..."
      File.readlines(intel_file).each {|line| intel_feed << line.chomp!}
    end
  
    proto = `tshark -r "#{ARGV[0]}" -T fields -e ip.proto 2>/dev/null`.split("\n").uniq
  
    if proto.include? "6"
      http_data = `tshark -R "http.request" -r "#{ARGV[0]}"  -T fields -e ip.dst -e tcp.dstport -e http.host -e http.request.uri 2>/dev/null`.split("\n").uniq
      https_data = `tshark -R "ssl.handshake.type==1" -r "#{ARGV[0]}"  -T fields -e ip.dst -e tcp.dstport -e ssl.handshake.extensions_server_name 2>/dev/null`.split("\n").uniq
			"\tmessage:\"suspected malicious http\";)"
		end
 
    if proto.include? "17"
      dns_data = `tshark -R "udp.dstport == 53" -r "#{ARGV[0]}"  -T fields -e ip.dst -e udp.dstport -e dns.qry.name  2>/dev/null`.split("\n").uniq
    end

		if http_data.any?
  		puts "\nHTTP Request\n"
  		http_data.each do |t|
 				data = t.split
  			dest_ip = data[0]
  			dest_port = data[1]
 				host = data[2]
 				uri = data[3]
 				if intel_feed.any?
 					puts "alert tcp any any -> #{dest_ip} #{dest_port} \\",
							 "\t(content:\"#{host}\"; http_header; \\",
							 "\tcontent:\"#{uri}\"; http_header; \\",
							 "\tmsg:\"suspected malicious http\";)" if intel_feed.include?(host)
 				else
 					puts "alert tcp any any -> #{dest_ip} #{dest_port} \\",
							 "\t(content:\"#{host}\"; http_header; \\",
							 "\tcontent:\"#{uri}\"; http_header; \\",
							 "\tmessage:\"suspected malicious http\";)"
 				end
 			end
 		end

		if https_data.any?
			puts "\nHTTPS Request\n"
			host = nil
			https_data.each do |t|
				data = t.split
				dest_ip = data[0]
				dest_port = data[1]
				host = data[2]
				if intel_feed.any? && !host.nil?
 					puts "alert tcp any any -> #{dest_ip} #{dest_port} \\",
 							 "\t(content:\"#{host}\"; msg:\"suspected malicious https\";)" if intel_feed.include?(host)
 				elsif !host.nil?
 					puts "alert tcp any any -> #{dest_ip} #{dest_port} \\",
 							 "\t(content:\"#{host}\"; msg:\"suspected malicious https\";)"
 				end
			end
		end

		if dns_data.any?
    	puts "\nDNS Request\n"
    	dns_data.each do |t|
      	data = t.split
      	dest_ip = data[0]
      	dest_port = data[1]
      	host = data[2]
				if intel_feed.any?
      		puts "alert udp any any -> #{dest_ip} #{dest_port} \\",
							 "\t(content:\"#{host}\"; message:\"suspected malicious host resolving\")" if intel_feed.include?(host)
				else
      		puts "alert udp any any -> #{dest_ip} #{dest_port} \\",
							 "\t(content:\"#{host}\"; message:\"suspected malicious host resolving\")"
    		end
			end
		end
 end


puts "\nUsing Tshark to retrieve fields and construct snort rules\n\n"

if (ARGV.length == 2) && (`file "#{ARGV[0]}"`.match(/tcpdump capture file/)) && (`file "#{ARGV[1]}"`.match(/ASCII text/))
	begin_analysis(ARGV[0], ARGV[1])
elsif (ARGV.length == 1) && (`file "#{ARGV[0]}"`.match(/tcpdump capture file/))
	begin_analysis(ARGV[0])
else
	puts "Usage - ./pcap_to_snort.rb [pcap]"
	puts "Usage - ./pcap_to_snort.rb [pcap] -i [intelligent feed txt file]"
  puts "\nNote: Intelligent feed txt file must not be empty"
  puts "\nExample - ./pcap_to_snort.rb <pcap file>"
  puts "\nExample - ./pcap_to_snort.rb <pcap file> -i <intelligent feed file>"
  puts
	exit
end

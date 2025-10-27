require 'damerau-levenshtein'
require 'time'

file = ARGV[0] || 'votes_48.txt'

start = Time.now

name_counts = Hash.new(0)
File.foreach(file) do |line|
  if line =~ /candidate:\s+(.+)$/
    name = $1.strip
    name_counts[name] += 1
  end
end

sorted_names = name_counts.keys.sort_by { |name| - name_counts[name] }

canonical_map = {}
used_names = []

sorted_names.each do |name|
  next if canonical_map[name]
  
  best_match = nil
  
  used_names.each do |used_name|
    distance = DamerauLevenshtein.distance(name, used_name)
    if distance <= 2
      best_match = used_name

    end
  end
  
  if best_match
    canonical_map[name] = best_match
  else
    canonical_map[name] = name
    used_names << name
  end
end


candidates = Hash.new(0)
candidate_to_times = Hash.new { |h, k| h[k] = [] }
ip_counts = Hash.new { |h, k| h[k] = Hash.new(0) }

File.foreach(file) do |line|
  if line =~ /candidate:\s+(.+)$/
    raw_name = $1.strip
    canonical_name = canonical_map[raw_name]
    
    candidates[canonical_name] += 1
    
    if line =~ /time:\s+(.+?), ip:/
      time_str = $1
      time = Time.parse(time_str)
      candidate_to_times[canonical_name] << time
    end

    if line =~ /ip:\s+([\d\.]+)/
      ip = $1
      ip_counts[canonical_name][ip] += 1
    end
  end
end

suspicious_ip = ip_counts.map do |cand, ips|
  repeats = ips.values.map { |count| [count - 1, 0].max }.sum
  [cand, repeats]
end.select { |_, r| r > 0 }.sort_by { |_, r| -r }

def max_burst(times, window = 60)
  return 0 if times.empty?
  times = times.sort
  left = 0
  mb = 1
  (1...times.size).each do |right|
    while times[right] - times[left] >= window && left < right
      left += 1
    end
    mb = [mb, right - left + 1].max
  end
  mb
end

suspicious_burst = candidate_to_times.map do |cand, times|
  burst = max_burst(times)
  [cand, burst]
end.sort_by { |_, b| -b }

cheaters = []
top_ip = suspicious_ip.first
cheaters << top_ip if top_ip

top_burst = suspicious_burst.find { |c, _| c != (top_ip ? top_ip[0] : nil) }
cheaters << top_burst if top_burst

puts "Обнаруженные подозрительные кандидаты:"
cheaters.each_with_index do |cheater, i|
  name, score = cheater
  type = suspicious_ip.map(&:first).include?(name) ? "Много голосов с одного IP" : "Много голосов за 60 сек"
  puts "#{i + 1}. #{name} — #{type} (#{score})"
end
  
puts "\nИтоговый рейтинг кандидатов:"
candidates.sort_by { |_, count| -count }.each_with_index do |candidate, i|
  puts "#{i + 1}. #{candidate[0]} - #{candidate[1]} голосов"
end

puts "\nВремя выполнения: #{(Time.now - start).round(3)} s"
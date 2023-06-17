# the file in which the blocked domains are
filename = 'blacklists/blocked_domains.txt'  

blocked_domains = []

with open(filename, 'r') as file:
    for line in file:
        if line.startswith("Blocked:"):
            domain = line.strip().replace("Blocked: ", "")
            blocked_domains.append(domain)

# how many of them contain 'google' and 'facebook'
google_count = sum('google' in domain for domain in blocked_domains)
facebook_count = sum('facebook' in domain for domain in blocked_domains)

print(f"Numar domenii ce contin 'google': {google_count}")
print(f"Numar domenii ce contin 'facebook': {facebook_count}")

# frequency dictionary
blocked_companies = {}
for domain in blocked_domains:
    company = domain.split('.')[1]
    if company in blocked_companies:
        blocked_companies[company] +=1
    else: 
        blocked_companies[company] = 1

sorted_companies = sorted(blocked_companies.items(), key=lambda x: x[1], reverse=True)

print("Cele mai frecvente companii:")
for company, count in sorted_companies:
    print(f"{company}: {count}")
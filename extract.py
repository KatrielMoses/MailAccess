import re

def extract(fname):
    try:
        content = open(fname, 'r', encoding='utf-16le').read()
    except Exception:
        try:
            content = open(fname, 'r', encoding='utf-8').read()
        except:
            return
    print(f'=== {fname} ===')
    # find summary bar
    summary_match = re.search(r'(?:┌|â”Œ).*?(?:└|â””)[^\n]*', content, re.DOTALL)
    if summary_match:
        print(summary_match.group(0))
    else:
        print('No summary bar found.')
    
    # find alternate emails
    alt_match = re.search(r'ALTERNATE EMAILS.*?(?=\n\n(?:──|Legend:))', content, re.DOTALL)
    if alt_match:
        print(alt_match.group(0))
    else:
        print('No alternate emails section found.')
    print()

extract('john_doe_out.txt')
extract('katriel_out.txt')

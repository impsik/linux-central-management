import re

# Simplified Debian version comparison
# Reference: https://www.debian.org/doc/debian-policy/ch-controlfields.html#version

def split_upstream_revision(version):
    if '-' in version:
        upstream, revision = version.rsplit('-', 1)
    else:
        upstream, revision = version, '0'
    return upstream, revision

def split_epoch(version):
    if ':' in version:
        epoch, rest = version.split(':', 1)
        return int(epoch), rest
    return 0, version

def get_non_digit_sequence(s):
    res = ""
    for char in s:
        if not char.isdigit():
            res += char
        else:
            break
    return res

def get_digit_sequence(s):
    res = ""
    for char in s:
        if char.isdigit():
            res += char
        else:
            break
    return res

def order(char):
    if char == '~':
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256

def compare_strings(s1, s2):
    while s1 or s2:
        first_diff1 = get_non_digit_sequence(s1)
        s1 = s1[len(first_diff1):]
        first_diff2 = get_non_digit_sequence(s2)
        s2 = s2[len(first_diff2):]
        
        # Compare non-digit part
        i = 0
        while i < len(first_diff1) or i < len(first_diff2):
            c1 = first_diff1[i] if i < len(first_diff1) else None
            c2 = first_diff2[i] if i < len(first_diff2) else None
            
            # End of string logic for tilde
            # If one runs out, check if the other starts with ~
            # But here we are comparing character by character
            
            val1 = order(c1) if c1 is not None else 0
            val2 = order(c2) if c2 is not None else 0
            
            # The standard says: 
            # "The lexical comparison is a comparison of ASCII values modified so that 
            # all the letters sort earlier than all the non-letters and so that a tilde 
            # sorts before anything, even the end of a part."
            
            # Wait, end of part?
            # Actually, standard algorithm iterates.
            
            if val1 != val2:
                return -1 if val1 < val2 else 1
            i += 1
            
        # Compare digit part
        digit1 = get_digit_sequence(s1)
        s1 = s1[len(digit1):]
        digit2 = get_digit_sequence(s2)
        s2 = s2[len(digit2):]
        
        val1 = int(digit1) if digit1 else 0
        val2 = int(digit2) if digit2 else 0
        
        if val1 != val2:
            return -1 if val1 < val2 else 1
            
    return 0

def compare_versions(v1, v2):
    """
    Compare two Debian version strings.
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
    """
    epoch1, rest1 = split_epoch(v1)
    epoch2, rest2 = split_epoch(v2)
    
    if epoch1 != epoch2:
        return -1 if epoch1 < epoch2 else 1
    
    upstream1, rev1 = split_upstream_revision(rest1)
    upstream2, rev2 = split_upstream_revision(rest2)
    
    cmp_upstream = compare_strings(upstream1, upstream2)
    if cmp_upstream != 0:
        return cmp_upstream
        
    return compare_strings(rev1, rev2)

def is_vulnerable(installed_version, fixed_version):
    """
    Returns True if installed_version < fixed_version.
    """
    return compare_versions(installed_version, fixed_version) < 0

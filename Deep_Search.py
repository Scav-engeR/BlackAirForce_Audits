import time
import webbrowser
import sys
import os
from colorama import Fore, Style, init
import urllib.parse

# Initialize colorama
init(autoreset=True)

class SocialMediaLookup:
    def __init__(self):
        self.results = []
        self.username = ""
        self.selected_operators = []
        self.use_browser_automation = False
        
    def display_banner(self):
        """Display the hacker-style banner"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        banner = f"""
{Fore.RED}
██████████                     █████       █████████                                        █████     
░░███░░░░███                   ░░███       ███░░░░░███                                      ░░███      
 ░███   ░░███  ██████   ██████  ░███ █████░███    ░░░   ██████   ██████   ████████   ██████  ░███████  
 ░███    ░███ ███░░███ ███░░███ ░███░░███ ░░█████████  ███░░███ ░░░░░███ ░░███░░███ ███░░███ ░███░░███ 
 ░███    ░███░███████ ░███████  ░██████░   ░░░░░░░░███░███████   ███████  ░███ ░░░ ░███ ░░░  ░███ ░███ 
 ░███    ███ ░███░░░  ░███░░░   ░███░░███  ███    ░███░███░░░   ███░░███  ░███     ░███  ███ ░███ ░███ 
 ██████████  ░░██████ ░░██████  ████ █████░░█████████ ░░██████ ░░████████ █████    ░░██████  ████ █████
░░░░░░░░░░    ░░░░░░   ░░░░░░  ░░░░ ░░░░░  ░░░░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░░      ░░░░░░  ░░░░ ░░░░░ 
                                                                                                       
                                                                                                       
                                                                                                       
{Style.RESET_ALL}
        """
        
        print(banner)
        
        description = f"""
{Fore.CYAN}[ TOOL DESCRIPTION ]{Style.RESET_ALL}
{Fore.WHITE}Advanced Social Media Intelligence Gathering Tool
Google-based OSINT with 25 advanced search operators
Customizable personal search operator selection
{Style.RESET_ALL}

{Fore.RED}Created by: {Fore.RED}D4rk_Intel{Style.RESET_ALL}
        """
        
        print(description)
        print("=" * 80)
        print()
    
    def get_user_preferences(self):
        """Get username and search preferences"""
        print(f"{Fore.GREEN}[+] Enter username to investigate:{Style.RESET_ALL}")
        self.username = input(f"{Fore.YELLOW}>>> {Style.RESET_ALL}").strip()
        
        if not self.username:
            print(f"{Fore.RED}[!] No username provided! Exiting...{Style.RESET_ALL}")
            sys.exit(1)
        
        # Ask about browser automation
        print(f"\n{Fore.GREEN}[+] Automate searches via browser?{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] This will open multiple browser tabs with Google search results{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[1] Yes - Open all searches in browser{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[2] No - Just generate search URLs{Style.RESET_ALL}")
        
        auto_choice = input(f"{Fore.YELLOW}>>> {Style.RESET_ALL}").strip()
        self.use_browser_automation = (auto_choice == "1")
        
        self.select_personal_search_operators()
            
        print(f"{Fore.GREEN}[+] Targeting: {Fore.CYAN}{self.username}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Search Engine: {Fore.CYAN}GOOGLE{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Browser Automation: {Fore.CYAN}{'ENABLED' if self.use_browser_automation else 'DISABLED'}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Selected Operators: {Fore.CYAN}{len(self.selected_operators)}{Style.RESET_ALL}")
        print()
    
    def select_personal_search_operators(self):
        """Let user choose from 25 advanced search operators in columns"""
        operators = [
            # Column 1: Social Media
            ("1", "Facebook", f'"{self.username}" site:facebook.com'),
            ("2", "Twitter", f'"{self.username}" site:twitter.com'),
            ("3", "Instagram", f'"{self.username}" site:instagram.com'),
            ("4", "LinkedIn", f'"{self.username}" site:linkedin.com'),
            ("5", "GitHub", f'"{self.username}" site:github.com'),
            
            # Column 2: More Platforms
            ("6", "Reddit", f'"{self.username}" site:reddit.com'),
            ("7", "YouTube", f'"{self.username}" site:youtube.com'),
            ("8", "TikTok", f'"{self.username}" site:tiktok.com'),
            ("9", "Pinterest", f'"{self.username}" site:pinterest.com'),
            ("10", "Telegram", f'"{self.username}" site:t.me'),
            
            # Column 3: Documents & Files
            ("11", "PDF Files", f'"{self.username}" filetype:pdf'),
            ("12", "Word Docs", f'"{self.username}" (filetype:doc OR filetype:docx)'),
            ("13", "Excel Files", f'"{self.username}" (filetype:xls OR filetype:xlsx)'),
            ("14", "Presentations", f'"{self.username}" (filetype:ppt OR filetype:pptx)'),
            ("15", "Text Files", f'"{self.username}" filetype:txt'),
            
            # Column 4: Advanced OSINT
            ("16", "In-Text Search", f'intext:"{self.username}"'),
            ("17", "In-URL Search", f'inurl:"{self.username}"'),
            ("18", "In-Title Search", f'intitle:"{self.username}"'),
            ("19", "Email Patterns", f'"{self.username}" "@gmail.com" OR "@yahoo.com"'),
            ("20", "Phone Numbers", f'"{self.username}" "phone" OR "mobile"'),
            
            # Column 5: More Advanced
            ("21", "Resumes/CVs", f'"{self.username}" "resume" OR "CV"'),
            ("22", "Location Data", f'"{self.username}" "address" OR "location"'),
            ("23", "Exclude Social", f'"{self.username}" -site:facebook.com -site:twitter.com'),
            ("24", "Forum Profiles", f'"{self.username}" site:forum OR site:boards'),
            ("25", "Blog Mentions", f'"{self.username}" site:blog OR site:medium.com'),
        ]
        
        print(f"\n{Fore.GREEN}[+] Select Personal Search Operators (comma-separated numbers){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Choose up to 25 operators for targeted investigation{Style.RESET_ALL}")
        print()
        
        # Display operators in columns
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│ {'NO.':<4} │ {'OPERATOR':<20} │ {'NO.':<4} │ {'OPERATOR':<20} │ {'NO.':<4} │ {'OPERATOR':<20} │{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        
        for i in range(0, len(operators), 3):
            row = []
            for j in range(3):
                if i + j < len(operators):
                    num, name, query = operators[i + j]
                    row.append(f"{num:<4} {name:<20}")
                else:
                    row.append(" " * 25)
            
            print(f"{Fore.WHITE}│ {row[0]} │ {row[1]} │ {row[2]} │{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}[+] Enter operator numbers (e.g., 1,3,5,7 or 'all' for all operators):{Style.RESET_ALL}")
        
        choice = input(f"{Fore.YELLOW}>>> {Style.RESET_ALL}").strip().lower()
        
        if choice == 'all':
            # Select all operators
            for num, name, query in operators:
                self.selected_operators.append((name, query))
        else:
            # Select specific operators
            selected_numbers = choice.split(',')
            selected_set = set()
            
            for num in selected_numbers:
                num = num.strip()
                if num.isdigit():
                    selected_set.add(num)
            
            for num, name, query in operators:
                if num in selected_set:
                    self.selected_operators.append((name, query))
        
        # If no operators selected, use default set
        if not self.selected_operators:
            print(f"{Fore.YELLOW}[!] No operators selected. Using default social media operators.{Style.RESET_ALL}")
            default_operators = ["1", "2", "3", "4", "5"]
            for num, name, query in operators:
                if num in default_operators:
                    self.selected_operators.append((name, query))
    
    def generate_search_urls(self):
        """Generate Google search URLs for selected operators"""
        print(f"{Fore.CYAN}[+] Generating Google Search URLs{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Creating advanced Google search queries...{Style.RESET_ALL}")
        print()
        
        all_urls = []
        
        for operator_name, query in self.selected_operators:
            print(f"{Fore.YELLOW}[GENERATING] {operator_name}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Query: {query}{Style.RESET_ALL}")
            
            encoded_query = urllib.parse.quote_plus(query)
            google_url = f"https://www.google.com/search?q={encoded_query}&num=50"
            all_urls.append(("google", operator_name, google_url))
            
            print(f"{Fore.GREEN}    ✓ Google URL generated{Style.RESET_ALL}")
            print()  # Space between operators
        
        print(f"{Fore.GREEN}[+] Generated {len(all_urls)} Google search URLs{Style.RESET_ALL}")
        return all_urls
    
    def open_urls_in_browser(self, urls):
        """Open URLs in browser with confirmation"""
        if not urls:
            print(f"{Fore.RED}[!] No URLs to open{Style.RESET_ALL}")
            return False
        
        if not self.use_browser_automation:
            print(f"{Fore.YELLOW}[!] Browser automation was disabled in settings{Style.RESET_ALL}")
            return False
            
        print(f"\n{Fore.YELLOW}[!] Ready to open {len(urls)} Google search URLs in browser{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] This will open multiple tabs in your default browser{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[?] Continue? (y/n): {Style.RESET_ALL}")
        
        choice = input().lower()
        
        if choice == 'y':
            print(f"{Fore.GREEN}[+] Opening {len(urls)} Google search pages in browser...{Style.RESET_ALL}")
            opened_count = 0
            
            for engine, operator_name, url in urls:
                try:
                    webbrowser.open_new_tab(url)
                    opened_count += 1
                    time.sleep(1)  # Prevent browser overload
                    print(f"{Fore.BLUE}    → {operator_name}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}    Error opening {operator_name}: {e}{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}[+] Successfully opened {opened_count} search pages{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.YELLOW}[!] Browser automation cancelled by user{Style.RESET_ALL}")
            return False
    
    def ask_save_or_modify(self, urls, urls_opened):
        """Ask user if they want to save, modify operators, or finish"""
        while True:
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[+] WHAT WOULD YOU LIKE TO DO NEXT?{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[1] Save Google search URLs to file{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[2] Go back and modify operator selection{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[3] Finish investigation without saving{Style.RESET_ALL}")
            
            choice = input(f"{Fore.YELLOW}>>> {Style.RESET_ALL}").strip()
            
            if choice == "1":
                return self.save_search_urls(urls)
            elif choice == "2":
                print(f"{Fore.BLUE}[+] Returning to operator selection...{Style.RESET_ALL}")
                # Clear previous selection and get new ones
                self.selected_operators = []
                self.select_personal_search_operators()
                
                # Regenerate URLs with new selection
                print(f"\n{Fore.GREEN}[+] Regenerating URLs with new operator selection...{Style.RESET_ALL}")
                new_urls = self.generate_search_urls()
                
                # Re-open in browser if previously enabled
                if urls_opened == "Yes":
                    print(f"{Fore.BLUE}[+] Re-opening new URLs in browser...{Style.RESET_ALL}")
                    self.open_urls_in_browser(new_urls)
                
                return self.ask_save_or_modify(new_urls, urls_opened)
            elif choice == "3":
                print(f"{Fore.YELLOW}[!] Finishing without saving...{Style.RESET_ALL}")
                return None
            else:
                print(f"{Fore.RED}[!] Invalid choice. Please select 1, 2, or 3.{Style.RESET_ALL}")
    
    def save_search_urls(self, urls):
        """Save search URLs to file"""
        filename = f"{self.username}_google_searches.txt"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"GOOGLE OSINT Search URLs for: {self.username}\n")
                f.write(f"Total Operators: {len(self.selected_operators)}\n")
                f.write(f"Total URLs: {len(urls)}\n")
                f.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                f.write("SELECTED OPERATORS:\n")
                f.write("-" * 20 + "\n")
                for name, query in self.selected_operators:
                    f.write(f"{name}: {query}\n")
                
                f.write(f"\nGOOGLE SEARCH URLs ({len(urls)}):\n")
                f.write("-" * 25 + "\n")
                for engine, operator, url in urls:
                    f.write(f"Operator: {operator}\n")
                    f.write(f"URL: {url}\n\n")
            
            print(f"{Fore.GREEN}[+] Google search URLs saved to: {filename}{Style.RESET_ALL}")
            return filename
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving file: {e}{Style.RESET_ALL}")
            return None
    
    def display_summary(self, urls, urls_opened, saved_file=None):
        """Display investigation summary"""
        total_urls = len(urls)
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] GOOGLE OSINT INVESTIGATION COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}┌─ Investigation Configuration{Style.RESET_ALL}")
        print(f"{Fore.GREEN}│   Target Username: {self.username}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}│   Search Engine: GOOGLE{Style.RESET_ALL}")
        print(f"{Fore.GREEN}│   Browser Automation: {'ENABLED' if self.use_browser_automation else 'DISABLED'}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}│   Operators Selected: {len(self.selected_operators)}{Style.RESET_ALL}")
        
        print(f"{Fore.BLUE}├─ Generated Resources{Style.RESET_ALL}")
        print(f"{Fore.BLUE}│   Google Search URLs: {total_urls}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}│   URLs Opened in Browser: {urls_opened}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}│   Results Saved: {'Yes' if saved_file else 'No'}{Style.RESET_ALL}")
        
        # Show operator categories
        categories = {}
        for name, query in self.selected_operators:
            if "site:" in query:
                if "facebook" in query: categories["Social Media"] = categories.get("Social Media", 0) + 1
                elif "twitter" in query: categories["Social Media"] = categories.get("Social Media", 0) + 1
                elif "instagram" in query: categories["Social Media"] = categories.get("Social Media", 0) + 1
                elif "linkedin" in query: categories["Professional"] = categories.get("Professional", 0) + 1
                elif "github" in query: categories["Development"] = categories.get("Development", 0) + 1
                else: categories["Websites"] = categories.get("Websites", 0) + 1
            elif "filetype:" in query:
                categories["Documents"] = categories.get("Documents", 0) + 1
            elif "intext" in query or "inurl" in query or "intitle" in query:
                categories["Advanced OSINT"] = categories.get("Advanced OSINT", 0) + 1
            else:
                categories["Personal Info"] = categories.get("Personal Info", 0) + 1
        
        print(f"{Fore.MAGENTA}└─ Operator Categories{Style.RESET_ALL}")
        for category, count in sorted(categories.items()):
            print(f"{Fore.MAGENTA}    {category}: {count} operators{Style.RESET_ALL}")
        
        print()
    
    def run_lookup(self):
        """Main function to run the social media lookup"""
        self.display_banner()
        self.get_user_preferences()
        
        print(f"{Fore.RED}[!] Starting Google OSINT investigation...{Style.RESET_ALL}")
        print()
        
        # Generate search URLs
        search_urls = self.generate_search_urls()
        
        # Open URLs in browser if enabled
        urls_opened = "Yes" if self.open_urls_in_browser(search_urls) else "No"
        
        # Ask user what to do next (save, modify, or finish)
        saved_file = self.ask_save_or_modify(search_urls, urls_opened)
        
        # Display final summary
        self.display_summary(search_urls, urls_opened, saved_file)
        
        if saved_file:
            print(f"{Fore.GREEN}[+] You can use the saved file to run searches later{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[✓] Google OSINT investigation completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Simple Structured Output for +Deep-Divin+{Style.RESET_ALL}")

def main():
    """Main execution function"""
    try:
        lookup_tool = SocialMediaLookup()
        lookup_tool.run_lookup()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Investigation interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Critical error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

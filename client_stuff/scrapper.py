from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from typing import List, Dict
from rich.console import Console
import json
import time
import pandas as pd
from openpyxl import load_workbook



console = Console()


def read_csv():
    df = pd.read_excel('Format NEW.xlsx', index_col=0)
    print(df.iloc[0,2])

quarter_mapping ={
    "Sep" :"Q2",
    "Jun" :"Q1",
    "Mar" :"Q4",
    "Dec" :"Q3",
}
def parse_data(dict_data:list[dict]) -> dict:


    # with open("indicator_data.json", "w+") as f:
    #     json.dump(dict_data, f)

    result = []
    
    
    # STEP [ 1 ] ----------------- parse the data in terms of quarters -------------------------------------------------
    for item in dict_data:
        indicator_data={}
        indicator_data["Indicators"] = item["Indicators"]
        for key, value in item.items():
            if key == "Indicators" or key == "Trend":
                continue
            new_key = quarter_mapping.get(key[:3], None)
            if not new_key:
                raise ValueError(f"Invalid quarter: {key}")
            new_key = new_key + " " + key[-3:]
            # indicator_data[new_key] = {"value":value , "month":key}
            indicator_data[new_key] = value
        result.append(indicator_data)

    # STEP [ 2 ] ----------------- add new indicators to the result -------------------------------------------------
    """
    Contribution = Total Income From Operations - Purchase of Traded Goods - Increase/Decrease in Stocks
    Op. EBITDA = Contribution - Employee Cost - Other expenses
    Op. EBIT = Op. EBITDA - Depreciation  
    Op. PBT = Op. EBIT - Interest
    PBT = Op. PBT + Other income
    """
    # getting all required data for calcs 
    for item in result:
        if item["Indicators"] == "Total Income From Operations" :
            total_income_from_operations = item
        if item["Indicators"] == "Purchase of Traded Goods" :
            purchase_of_traded_goods = item
        if item["Indicators"] == "Increase/Decrease in Stocks" :
            increase_decrease_in_stocks = item
        if item["Indicators"] == "Employees Cost" :
            employee_cost = item
        if item["Indicators"] == "Other Expenses" :
            other_expenses = item
        if item["Indicators"] == "Depreciation" :
            depreciation = item
        if item["Indicators"] == "Interest" :
            interest = item
        if item["Indicators"] == "Other Income" :
            other_income = item
    if not total_income_from_operations or not purchase_of_traded_goods or not increase_decrease_in_stocks or not employee_cost or not other_expenses or not depreciation or not interest or not other_income:
        raise ValueError("Total Income From Operations, Purchase of Traded Goods, Increase/Decrease in Stocks, Employee Cost, Other expenses, Depreciation, Interest, Other income are required for calcs")

    
    # for contribution calculation
    contribution = {}
    for key in total_income_from_operations.keys():
        if key == "Indicators":
            contribution["Indicators"] = "Contribution"
            continue
        console.print(f"Total Income From Operations : {total_income_from_operations[key]} , Purchase of Traded Goods : {purchase_of_traded_goods[key]} , Increase/Decrease in Stocks : {increase_decrease_in_stocks[key]}", style="bold green")
        contribution[key] = int(total_income_from_operations[key].replace(",", "")) - int(purchase_of_traded_goods[key].replace(",", "")) - int(increase_decrease_in_stocks[key].replace(",", ""))
    console.print(f"Contribution : {contribution}", style="bold green")
    result.append(contribution)

    
    # for op. ebitda calculation
    op_ebitda = {}
    for key in employee_cost.keys():
        if key == "Indicators":
            op_ebitda["Indicators"] = "Op. EBITDA"
            continue
        op_ebitda[key] = contribution[key] - int(employee_cost[key].replace(",", "")) - int(other_expenses[key].replace(",", ""))
    console.print(f"Op. EBITDA : {op_ebitda}", style="bold green")
    result.append(op_ebitda)

    # for op. ebit calculation
    op_ebit = {}
    for key in depreciation.keys():
        if key == "Indicators":
            op_ebit["Indicators"] = "Op. EBIT"
            continue
        op_ebit[key] = op_ebitda[key] - int(depreciation[key].replace(",", ""))
    console.print(f"Op. EBIT : {op_ebit}", style="bold green")
    result.append(op_ebit)

    # for op. pbt calculation
    op_pbt = {}
    for key in interest.keys():
        if key == "Indicators":
            op_pbt["Indicators"] = "Op. PBT"
            continue
        op_pbt[key] = op_ebit[key] - int(interest[key].replace(",", ""))
    console.print(f"Op. PBT : {op_pbt}", style="bold green")
    result.append(op_pbt)

    # for pbt calculation
    pbt = {}
    for key in other_income.keys():
        if key == "Indicators":
            pbt["Indicators"] = "PBT"
            continue
        pbt[key] = op_pbt[key] + int(other_income[key].replace(",", ""))
    console.print(f"PBT : {pbt}", style="bold green")
    result.append(pbt)


    
    return result
            
            


def create_company_dataframe(data:dict) -> pd.DataFrame:
    # STEP [ 1 ] ----------------- define columns of the dataframe -------------------------------------------------
    temp = data[0]
    init_data = { key : [] for key , value in temp.items() }
    df = pd.DataFrame(init_data)
    console.print(f"Dataframe created with columns : {df.columns}", style="bold green")

    # STEP [ 2 ] ----------------- add data to the dataframe -------------------------------------------------
    for item in data:
        df.loc[len(df)] = item
    console.print(f"Data added to the dataframe : {df.head()}", style="bold green")

    # STEP [ 3 ] ----------------- save the dataframe to a excel file -------------------------------------------------
    df.to_excel("company_dataframe.xlsx", index=False)
    console.print(f"Dataframe saved to excel file", style="bold green")
    return df


def scrape_quarterly_financials(url: str, headless: bool = True) -> List[Dict]:
    """
    Scrapes quarterly financials table data from Moneycontrol website using Selenium.
    
    Args:
        url: The URL of the Moneycontrol quarterly results page
        headless: Whether to run the browser in headless mode (default: True)
        
    Returns:
        List of dictionaries containing quarterly financial data
    """
    driver = None
    try:
        # Configure Chrome options
        chrome_options = Options()
        if headless:
            chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        
        console.print(f"Initializing Chrome WebDriver...", style="bold blue")
        driver = webdriver.Chrome(options=chrome_options)
        
        console.print(f"Fetching data from: {url}", style="bold blue")
        driver.get(url)
        
        # Wait for the page to load
        time.sleep(3)
        
        # Wait for the quarterly_results div to be present
        console.print("Waiting for quarterly_results div...", style="bold yellow")
        wait = WebDriverWait(driver, 20)
        quarterly_results_div = wait.until(
            EC.presence_of_element_located((By.ID, "quarterly_results"))
        )
        console.print("Found div with id='quarterly_results'", style="bold green")
        
        # Find the div inside with a class that starts with "table"
        console.print("Searching for div with class starting with 'table'...", style="bold yellow")
        table_container_div = None
        
        # Find all divs inside quarterly_results
        divs = quarterly_results_div.find_elements(By.TAG_NAME, "div")
        
        for div in divs:
            class_attr = div.get_attribute("class")
            if class_attr:
                classes = class_attr.split()
                for class_name in classes:
                    if class_name.startswith('table'):
                        table_container_div = div
                        console.print(f"Found div with class starting with 'table': {class_name}", style="bold green")
                        break
            if table_container_div:
                break
        
        if not table_container_div:
            console.print("Could not find div with class starting with 'table' inside quarterly_results", style="bold red")
            return []
        
        # Find the table inside that div
        console.print("Looking for table element...", style="bold yellow")
        quarterly_table = table_container_div.find_element(By.TAG_NAME, "table")
        
        if not quarterly_table:
            console.print("Could not find table inside the table container div", style="bold red")
            return []
        
        console.print("Found quarterly financials table", style="bold green")
        
        # Extract table headers
        headers = []
        try:
            # Try to find thead first
            thead = quarterly_table.find_element(By.TAG_NAME, "thead")
            header_row = thead.find_element(By.TAG_NAME, "tr")
        except:
            # If no thead, get first tr
            header_row = quarterly_table.find_element(By.TAG_NAME, "tr")
        
        header_cells = header_row.find_elements(By.TAG_NAME, "th")
        if not header_cells:
            # If no th elements, try td
            header_cells = header_row.find_elements(By.TAG_NAME, "td")
        
        headers = [cell.text.strip() for cell in header_cells]
        console.print(f"Table headers: {headers}", style="bold cyan")
        
        # Extract table rows (data rows)
        quarterly_data = []
        rows = quarterly_table.find_elements(By.TAG_NAME, "tr")
        
        # Skip the header row
        data_rows = rows[1:] if len(rows) > 1 else rows
        
        for row in data_rows:
            cells = row.find_elements(By.TAG_NAME, "td")
            if len(cells) < 2:  # Skip rows with insufficient data
                continue
            
            row_data = {}
            for idx, cell in enumerate(cells):
                header = headers[idx] if idx < len(headers) else f"Column_{idx}"
                value = cell.text.strip()
                # Clean up the value (remove extra whitespace, newlines)
                value = ' '.join(value.split())
                row_data[header] = value
            
            if row_data:  # Only add non-empty rows
                quarterly_data.append(row_data)
        
        console.print(f"Extracted {len(quarterly_data)} rows of quarterly data", style="bold green")
        return quarterly_data
        
    except Exception as e:
        console.print(f"Error scraping the webpage: {e}", style="bold red")
        raise
    finally:
        if driver:
            driver.quit()
            console.print("Browser closed", style="bold yellow")


def save_to_json(data: List[Dict], filename: str = "quarterly_financials.json"):
    """
    Saves the scraped data to a JSON file.
    
    Args:
        data: List of dictionaries containing the scraped data
        filename: Output filename for the JSON file
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"Data saved to {filename}", style="bold green")
    except Exception as e:
        console.print(f"Error saving to file: {e}", style="bold red")
        raise

def save_to_excel(df1: pd.DataFrame, companies_df: list[pd.DataFrame], filename: str = "quarterly_financials.xlsx"):
    """
    Saves the scraped data to an Excel file.
    
    Args:
        data: List of dictionaries containing the scraped data
        filename: Output filename for the Excel file
    """
    try:
        # Generating workbook and writer engine
        excel_workbook = load_workbook("xl_file.xlsx")
        writer = pd.ExcelWriter("xl_file.xlsx", engine='openpyxl')
        writer.book = excel_workbook

        # Creating dataframes with different values
        data_1 = {'Column1': [11, 22, 33], 'Column2': ['value11', 'value22', 'value33']}
        data_2 = {'A': [111, 222, 333], 'B': ['X', 'Y', 'Z']}
        df_1 = pd.DataFrame(data_1)
        df_2 = pd.DataFrame(data_2)

        # Adding dataframes to Excel as new sheets
        df_1.to_excel(writer, sheet_name='Quarterly Financials', index=False)
        for company_df in companies_df:
            company_df.to_excel(writer, sheet_name=company_df['Company Name'], index=False)

        # Saving changes and closing writer
        writer.save()
        writer.close()
    except Exception as e:
        console.print(f"Error saving to file: {e}", style="bold red")
        raise


def print_table_data(data: List[Dict]):
    """
    Pretty prints the scraped table data.
    
    Args:
        data: List of dictionaries containing the scraped data
    """
    if not data:
        console.print("No data to display", style="bold yellow")
        return
    
    console.print("\n" + "="*80, style="bold cyan")
    console.print("QUARTERLY FINANCIALS DATA", style="bold cyan")
    console.print("="*80 + "\n", style="bold cyan")
    
    for idx, row in enumerate(data, 1):
        console.print(f"Row {idx}:", style="bold yellow")
        for key, value in row.items():
            console.print(f"  {key}: {value}", style="white")
        console.print()

companies = {

    "Wipro" : "https://www.moneycontrol.com/markets/financials/quarterly-results/wipro-w/",
    "TCS" : "https://www.moneycontrol.com/markets/financials/quarterly-results/tataconsultancyservices-TCS/",
    "Infosys" : "https://www.moneycontrol.com/markets/financials/quarterly-results/infosys-IT/",
    "LTIMindtree" : "https://www.moneycontrol.com/markets/financials/quarterly-results/ltimindtree-LI12/",
    "HCL Technologies" : "https://www.moneycontrol.com/markets/financials/quarterly-results/hcltechnologies-HCL02/",
    "Persistent systems" : "https://www.moneycontrol.com/markets/financials/quarterly-results/persistentsystems-PS15/", 
    "Tech Mahindra" : "https://www.moneycontrol.com/markets/financials/quarterly-results/techmahindra-tm4/",
    "Cyient" : "https://www.moneycontrol.com/markets/financials/quarterly-results/cyientdlm-CD02/",
    "LT Technology" : "https://www.moneycontrol.com/markets/financials/quarterly-results/lttechnologyservices-lts/",
    "Services Coforge" : "https://www.moneycontrol.com/markets/financials/quarterly-results/coforge-NII02/",
    "mphasis" : "https://www.moneycontrol.com/markets/financials/quarterly-results/mphasis-mb02/",
    "zensar" : "https://www.moneycontrol.com/markets/financials/nine-months-results/zensartechnologies-zt02/",
    "Hexaware" : "https://www.moneycontrol.com/markets/financials/quarterly-results/hexawaretechnologies-HTL03/",
    "Birlasoft" : "https://www.moneycontrol.com/markets/financials/quarterly-results/birlasoft-kpi02/",
}
if __name__ == "__main__":
    # URL to scrape
    url = companies["Wipro"]
    
    try:
        # Scrape the quarterly financials
        quarterly_data = scrape_quarterly_financials(url, headless=True)
        parsed_data = parse_data(quarterly_data)
        company_df = create_company_dataframe(parsed_data)
        # Display the data
        # print_table_data(quarterly_data)
        
        # Save to Excel file
        # save_to_json(map_to_quarters(quarterly_data),"quarterly_financials.json")
        
        # console.print("\nScraping completed successfully!", style="bold green")
        
    except Exception as e:
        console.print(f"\nScraping failed: {e}", style="bold red")
        raise

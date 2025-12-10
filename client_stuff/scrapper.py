import copy
from openpyxl.worksheet import worksheet
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from typing import List, Dict
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
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

heading_data = { 
    "Revenue" : [], 
    "Op. EBITDA %" : [],
    "Op. EBIT %" : [],
    "Op. PBT" : [],
    "PBT" : [],
}

def convert_values_to_int(data:dict) -> dict:
    for key, value in data.items():
        if key == "Indicators":
            continue
        if value == "--":
            data[key] = 0
            continue
        data[key] = int(value.replace(",", ""))
    return data

def prepare_for_quarterly_dataframe(data:dict,company_name:str) -> dict:
    data.pop("Indicators")
    result = { "Company Name" : company_name }
    for key , value in data.items():
        result[key] = value
    return result

def sort_quarter_key(q):
        # if key is "Company Name" or "Indicators" , return 0
        # Handle format like "Q2 '25" or "Q2'25"
        q_clean = q.replace(" ", "")
        if "'" in q_clean:
            parts = q_clean.split("'")
            quarter = parts[0].strip()
            year = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            q_num = int(quarter[1]) if len(quarter) > 1 and quarter[1].isdigit() else 0
            return (-year, -q_num)  # Negative for descending (most recent first)
        return (0, 0)
    
def parse_data(dict_data:list[dict] , company_name:str) -> dict:


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
    total_income_from_operations , purchase_of_traded_goods , increase_decrease_in_stocks , employee_cost , other_expenses , depreciation , interest , other_income = None, None, None, None, None, None, None, None
    # getting all required data for calcs 
    for item in result:
        if item["Indicators"] == "Total Income From Operations" :
            total_income_from_operations = convert_values_to_int(item)
        if item["Indicators"] == "Purchase of Traded Goods" :
            purchase_of_traded_goods = convert_values_to_int(item)
        if item["Indicators"] == "Increase/Decrease in Stocks" :
            increase_decrease_in_stocks = convert_values_to_int(item)
        if item["Indicators"] == "Employees Cost" :
            employee_cost = convert_values_to_int(item)
        if item["Indicators"] == "Other Expenses" :
            other_expenses = convert_values_to_int(item)
        if item["Indicators"] == "Depreciation" or item["Indicators"] == "Depreciation & Amortization" or item["Indicators"] == "depreciat":
            depreciation = convert_values_to_int(item)
        if item["Indicators"] == "Interest" :
            interest = convert_values_to_int(item)
        if item["Indicators"] == "Other Income" :
            other_income = convert_values_to_int(item)
    if not total_income_from_operations or not purchase_of_traded_goods or not increase_decrease_in_stocks or not employee_cost or not other_expenses or not depreciation or not interest or not other_income:
        raise ValueError("Total Income From Operations, Purchase of Traded Goods, Increase/Decrease in Stocks, Employee Cost, Other expenses, Depreciation, Interest, Other income are required for calcs")

    
    # profitability metrics seperator 
    percentage_separator_blank = {
        "Indicators" : None,
    }
    percentage_separator = {
        "Indicators" : "Profitability Metrics",
    }
    for key in total_income_from_operations.keys():
        if key == "Indicators":
            continue
        percentage_separator[key] = None
        percentage_separator_blank[key] = None
    result.append(percentage_separator_blank)
    result.append(percentage_separator)
    result.append(percentage_separator_blank)

    # for op revenue growth % calculation
    op_revenue_growth_rate = {}
    last_seen = None
    for key in reversed(list(total_income_from_operations.keys())):
        if key == "Indicators":
            op_revenue_growth_rate["Indicators"] = "Operating Revenue Growth Rate"
            continue
        
        value = total_income_from_operations[key]
        if last_seen is None:
            # First quarter (most recent) - no growth to calculate
            op_revenue_growth_rate[key] = "N/A"
            last_seen = value
            continue
        
        if last_seen == 0:
            op_revenue_growth_rate[key] = "0.000%"
            last_seen = value
            continue
        # Growth formula: (Current - Previous) / Previous * 100
        op_revenue_growth_rate[key] = str(round((value - last_seen) / last_seen * 100 , 3)) + "%"
        last_seen = value
    
    # quarrters are reversed at this point , so we need to reverse it back
    formatted_op_revenue_growth_rate = {"Indicators" : "Operating Revenue Growth Rate"}
    for key in reversed(list(op_revenue_growth_rate.keys())):
        if key == "Indicators":
            formatted_op_revenue_growth_rate["Indicators"] = "Operating Revenue Growth Rate"
            continue
        formatted_op_revenue_growth_rate[key] = op_revenue_growth_rate[key]
    result.append(formatted_op_revenue_growth_rate)


    # for contribution calculation
    contribution = {}
    for key in total_income_from_operations.keys():
        if key == "Indicators":
            contribution["Indicators"] = "Contribution"
            continue
        contribution[key] = total_income_from_operations[key] - purchase_of_traded_goods[key] - increase_decrease_in_stocks[key]
    result.append(contribution)

    
    # for op. ebitda calculation
    op_ebitda = {}
    for key in employee_cost.keys():
        if key == "Indicators":
            op_ebitda["Indicators"] = "Op. EBITDA"
            continue
        op_ebitda[key] = contribution[key] - employee_cost[key] - other_expenses[key]
    result.append(op_ebitda)

    # for op. ebit calculation
    op_ebit = {}
    for key in depreciation.keys():
        if key == "Indicators":
            op_ebit["Indicators"] = "Op. EBIT"
            continue
        op_ebit[key] = op_ebitda[key] - depreciation[key]
    result.append(op_ebit)

    # for op. pbt calculation
    op_pbt = {}
    for key in interest.keys():
        if key == "Indicators":
            op_pbt["Indicators"] = "Op. PBT"
            continue
        op_pbt[key] = op_ebit[key] - interest[key]
    result.append(op_pbt)

    # for pbt calculation
    pbt = {}
    for key in other_income.keys():
        if key == "Indicators":
            pbt["Indicators"] = "PBT"
            continue
        pbt[key] = op_pbt[key] + other_income[key]
    result.append(pbt)

    
    # adding seperator
    percentage_separator = {
        "Indicators" : "% Of Revenue ( Total Income From Operations )",
    }
    for key in total_income_from_operations.keys():
        if key == "Indicators":
            continue
        percentage_separator[key] = None
    result.append(percentage_separator_blank)
    result.append(percentage_separator)
    result.append(percentage_separator_blank)

    
    
    # for contribution % calculation
    contribution_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            contribution_percentage["Indicators"] = "Contribution %"
            continue
        contribution_percentage[key] = round((contribution[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(contribution_percentage)

    # for employees cost % calculation
    employees_cost_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            employees_cost_percentage["Indicators"] = "Employees Cost %"
            continue
        employees_cost_percentage[key] = round((employee_cost[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(employees_cost_percentage)

    # for Other expenses % calculation
    other_expenses_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            other_expenses_percentage["Indicators"] = "Other Expenses %"
            continue
        other_expenses_percentage[key] = round((other_expenses[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(other_expenses_percentage)

    # for Op. EBITDA % calculation
    op_ebitda_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            op_ebitda_percentage["Indicators"] = "Op. EBITDA %"
            continue
        op_ebitda_percentage[key] = round((op_ebitda[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(op_ebitda_percentage)


    # for Op. EBIT % calculation
    op_ebit_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            op_ebit_percentage["Indicators"] = "Op. EBIT %"
            continue
        op_ebit_percentage[key] = round((op_ebit[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(op_ebit_percentage)

    # for Op. PBT % calculation
    op_pbt_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            op_pbt_percentage["Indicators"] = "Op. PBT %"
            continue
        op_pbt_percentage[key] = round((op_pbt[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(op_pbt_percentage)

    # for PBT % calculation
    pbt_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            pbt_percentage["Indicators"] = "PBT %"
            continue
        pbt_percentage[key] = round((pbt[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(pbt_percentage)

    # for Depreciation % calculation
    depreciation_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            depreciation_percentage["Indicators"] = "Depreciation %"
            continue
        depreciation_percentage[key] = round((depreciation[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(depreciation_percentage)

    # for Interest % calculation
    interest_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            interest_percentage["Indicators"] = "Finance Costs / Interest %"
            continue
        interest_percentage[key] = round((interest[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(interest_percentage)
    
    # for other income % calculation
    other_income_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            other_income_percentage["Indicators"] = "Other Income %"
            continue
        other_income_percentage[key] = round((other_income[key] / total_income_from_operations[key]) * 100, 3) 
    result.append(other_income_percentage)
    
    
    
    console.print(f"Profitability metrics calculated successfully", style="bold green")

    
    copy_of_total_income_from_operations = copy.deepcopy(total_income_from_operations)
    copy_of_op_ebitda_percentage = copy.deepcopy(op_ebitda_percentage)
    copy_of_op_ebit_percentage = copy.deepcopy(op_ebit_percentage)
    copy_of_op_pbt = copy.deepcopy(op_pbt)
    copy_of_pbt = copy.deepcopy(pbt)
    
    return (result,{
        "Revenue" : prepare_for_quarterly_dataframe(copy_of_total_income_from_operations,company_name),
        "Op. EBITDA %" : prepare_for_quarterly_dataframe(copy_of_op_ebitda_percentage,company_name),
        "Op. EBIT %" : prepare_for_quarterly_dataframe(copy_of_op_ebit_percentage,company_name),
        "Op. PBT" : prepare_for_quarterly_dataframe(copy_of_op_pbt,company_name),
        "PBT" : prepare_for_quarterly_dataframe(copy_of_pbt,company_name),
    })
            


def create_blank_row(cols:list , text:str) -> dict:
    blank_row = { "Company Name" : text }
    for col in cols:
        if col == "Company Name":
            continue
        blank_row[col] = None
    return blank_row

def create_quarterly_dataframe(companies_data:dict) -> pd.DataFrame:
    """
    Dataframe row structure : 
    {
        "Company Name" : [],
        "Q1 '25" : [] ,
        "Q2 '25" : [] ,
        "Q3 '25" : [] ,
        "Q4 '25" : [] ,
        and so on 
    }
    """

    # creating dataframe
    df_list = []
    for heading , data in heading_data.items():
        df_init = { "Company Name" : [] }
        cols = list(data[0].keys())
        for col in cols:
            if col == "Company Name":
                continue
            df_init[col] = []
        df = pd.DataFrame(df_init)
        df.loc[len(df)] = create_blank_row(cols, heading)
        df.loc[len(df)] = create_blank_row(cols, "")
        for item in data:
            df.loc[len(df)] = item
        
        df.loc[len(df)] = create_blank_row(cols, "")
        df_list.append(df)
        # df.to_excel(f"{heading}_data.xlsx", index=False)
    
    merged_df = pd.concat(df_list)
    merged_df.to_excel("quarterly_financials.xlsx", index=False)
    return merged_df



def create_company_dataframe(data:dict,company_name:str="Company",save_checkpoint:bool=True) -> pd.DataFrame:
    
    # STEP [ 1 ] ----------------- define columns of the dataframe -------------------------------------------------
    temp = data[0]
    init_data = { key : [] for key , value in temp.items() }
    df = pd.DataFrame(init_data)
    # console.print(f"Dataframe created with columns : {" ".join(list(df.columns))}", style="bold green")

    # STEP [ 2 ] ----------------- add data to the dataframe -------------------------------------------------
    for item in data:
        df.loc[len(df)] = item
    console.print(f"Data added to the dataframe successfully", style="bold green")

    # STEP [ 3 ] ----------------- save the dataframe to a excel file -------------------------------------------------
    if save_checkpoint:
        df.to_excel(f"{company_name}_finanicial_data.xlsx", index=False)
        console.print(f"Dataframe saved to excel file {company_name}_finanicial_data.xlsx successfully", style="bold green")
    
    console.print(f"Dataframe created successfully", style="bold green")
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
        time.sleep(8)
        
        # Wait for the quarterly_results div to be present
        # console.print("Waiting for quarterly_results div...", style="bold yellow")
        wait = WebDriverWait(driver, 20)
        quarterly_results_div = wait.until(
            EC.presence_of_element_located((By.ID, "quarterly_results"))
        )
        if quarterly_results_div:
            console.print("Found div with id='quarterly_results'", style="bold green")
        
        # Find the div inside with a class that starts with "table"
        # console.print("Searching for div with class starting with 'table'...", style="bold yellow")
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
                        # console.print(f"Found div with class starting with 'table': {class_name}", style="bold green")
                        break
            if table_container_div:
                break
        
        if not table_container_div:
            console.print("Could not find div with class starting with 'table' inside quarterly_results", style="bold red")
            return []
        
        # Find the table inside that div
        # console.print("Looking for table element...", style="bold yellow")  
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
        # console.print(f"Table headers: {headers}", style="bold cyan")
        
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




def save_companies_to_excel(companies_df: list[tuple[str,pd.DataFrame]], filename: str):
    """
    Saves the scraped data to an Excel file.
    
    Args:
        companies_df: List of dataframes containing the scraped data
        filename: Output filename for the Excel file
    """
    try:
        writer = pd.ExcelWriter(filename, engine='openpyxl')

        for company_name, company_df in companies_df:
            company_df.to_excel(writer, sheet_name=company_name, index=False)

        writer.close()
    except Exception as e:
        console.print(f"Error saving to file: {e}", style="bold red")
        raise



def add_more_headings(heading_data:dict) -> dict:

    
    # adding revenue growth % 
    heading_data["Revenue Growth Rate"] = []
    revenue = heading_data["Revenue"]
    for company_data in revenue:
        new_company_data = { "Company Name" : company_data["Company Name"] }
        last_seen = None
        for key in reversed(list(company_data.keys())):
            if key == "Company Name":
                continue
            if isinstance(company_data[key], str):
                value = int(company_data[key].replace(",", ""))
            else:
                value = company_data[key]
            
            if last_seen is None:
                # First quarter (most recent) - no growth to calculate
                new_company_data[key] = "N/A"
                last_seen = value
                continue
            
            if last_seen == 0:
                new_company_data[key] = "0.000%"
                last_seen = value
                continue
            # Growth formula: (Current - Previous) / Previous * 100
            new_company_data[key] = str(round((value - last_seen) / last_seen * 100, 3)) + "%"
            last_seen = value
        
        #resetting the quarter keys to original order
        formatted_new_company_data = {"Company Name" : new_company_data["Company Name"]}
        for key in reversed(list(new_company_data.keys())):
            if key == "Company Name":
                continue
            formatted_new_company_data[key] = new_company_data[key]
        heading_data["Revenue Growth Rate"].append(formatted_new_company_data)
    
    # adding Op. EBITDA Growth (Bps)
    heading_data["Op. EBITDA Growth (Bps)"] = []
    op_ebitda_percent = heading_data["Op. EBITDA %"]
    for company_data in op_ebitda_percent:
        new_company_data = { "Company Name" : company_data["Company Name"] }
        last_seen = None
        for key in reversed(list(company_data.keys())):
            if key == "Company Name":
                continue
            value = company_data[key]
            
            if last_seen is None:
                # First quarter (most recent) - no growth to calculate
                new_company_data[key] = "N/A"
                last_seen = value
                continue
            
            if last_seen == 0:
                new_company_data[key] = "0.000"
                last_seen = value
                continue
            # Calculate basis points change: (current - previous) * 100
            # Since input is already a percentage, basis points = percentage change * 100
            bps_value = round((value - last_seen) * 100, 3)
            new_company_data[key] = str(bps_value)
            last_seen = value
        
        #resetting the quarter keys to original order
        formatted_new_company_data = {"Company Name" : new_company_data["Company Name"]}
        for key in reversed(list(new_company_data.keys())):
            if key == "Company Name":
                continue
            formatted_new_company_data[key] = new_company_data[key]
        heading_data["Op. EBITDA Growth (Bps)"].append(formatted_new_company_data)
    
    # adding Op. EBIT Growth (Bps)
    heading_data["Op. EBIT Growth (Bps)"] = []
    op_ebit_percent = heading_data["Op. EBIT %"]
    for company_data in op_ebit_percent:
        new_company_data = { "Company Name" : company_data["Company Name"] }
        last_seen = None
        for key in reversed(list(company_data.keys())):
            if key == "Company Name":
                continue
            value = company_data[key]
            
            if last_seen is None:
                # First quarter (most recent) - no growth to calculate
                new_company_data[key] = "N/A"
                last_seen = value
                continue
            
            if last_seen == 0:
                new_company_data[key] = "0.000"
                last_seen = value
                continue
            # Calculate basis points change: (current - previous) * 100
            # Since input is already a percentage, basis points = percentage change * 100
            bps_value = round((value - last_seen) * 100, 3)
            new_company_data[key] = str(bps_value)
            last_seen = value
        
        #resetting the quarter keys to original order
        formatted_new_company_data = {"Company Name" : new_company_data["Company Name"]}
        for key in reversed(list(new_company_data.keys())):
            if key == "Company Name":
                continue
            formatted_new_company_data[key] = new_company_data[key]
        heading_data["Op. EBIT Growth (Bps)"].append(formatted_new_company_data)
    
    # adding Op. PBT growth
    heading_data["Op. PBT growth"] = []
    op_pbt = heading_data["Op. PBT"]
    for company_data in op_pbt:
        new_company_data = { "Company Name" : company_data["Company Name"] }
        last_seen = None
        for key in reversed(list(company_data.keys())):
            if key == "Company Name":
                continue
            if isinstance(company_data[key], str):
                value = int(company_data[key].replace(",", ""))
            else:
                value = company_data[key]
            
            if last_seen is None:
                # First quarter (most recent) - no growth to calculate
                new_company_data[key] = "N/A"
                last_seen = value
                continue
            
            if last_seen == 0:
                new_company_data[key] = "0.000%"
                last_seen = value
                continue
            # Growth formula: (Current - Previous) / Previous * 100
            new_company_data[key] = str(round((value - last_seen) / last_seen * 100, 3)) + "%"
            last_seen = value
        
        #resetting the quarter keys to original order
        formatted_new_company_data = {"Company Name" : new_company_data["Company Name"]}
        for key in reversed(list(new_company_data.keys())):
            if key == "Company Name":
                continue
            formatted_new_company_data[key] = new_company_data[key]
        heading_data["Op. PBT growth"].append(formatted_new_company_data)
    
    # adding PBT growth
    heading_data["PBT growth"] = []
    pbt = heading_data["PBT"]
    for company_data in pbt:
        new_company_data = { "Company Name" : company_data["Company Name"] }
        last_seen = None
        for key in reversed(list(company_data.keys())):
            if key == "Company Name":
                continue
            if isinstance(company_data[key], str):
                value = int(company_data[key].replace(",", ""))
            else:
                value = company_data[key]
            
            if last_seen is None:
                # First quarter (most recent) - no growth to calculate
                new_company_data[key] = "N/A"
                last_seen = value
                continue
            
            if last_seen == 0:
                new_company_data[key] = "0.000%"
                last_seen = value
                continue
            # Growth formula: (Current - Previous) / Previous * 100
            new_company_data[key] = str(round((value - last_seen) / last_seen * 100, 3)) + "%"
            last_seen = value

        #resetting the quarter keys to original order
        formatted_pbt_growth = {"Company Name" : new_company_data["Company Name"]}
        for key in reversed(list(new_company_data.keys())):
            if key == "Company Name":
                continue
            formatted_pbt_growth[key] = new_company_data[key]
        heading_data["PBT growth"].append(formatted_pbt_growth)
    
    
    return heading_data
    

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

def write_column( col_no : int , data:list[tuple] , worksheet:worksheet.Worksheet , start_row:int = 1 , end_row:int = None) -> None:
    if end_row is None:
        end_row = len(data)

    i=0
    for row in range(start_row, end_row + 1):
        worksheet.cell(row=row, column=col_no).value = data[i][0]
        try:
            worksheet.cell(row=row, column=col_no).font = data[i][1]
            worksheet.cell(row=row, column=col_no).fill = data[i][2]
        except IndexError:
            # console.print(f"Skipping font formatting for row {row} and column {col_no}", style="bold yellow")
            pass
        i+=1
    return

def write_row( row_no : int , data:list[tuple] , worksheet:worksheet.Worksheet , start_col:int = 1 , end_col:int = None) -> None:
    if end_col is None:
        end_col = len(data)
    i=0
    for col in range(start_col, end_col + 1):
        worksheet.cell(row=row_no, column=col).value = data[i][0]
        try:
            worksheet.cell(row=row_no, column=col).font = data[i][1]
            worksheet.cell(row=row_no, column=col).fill = data[i][2]
        except IndexError:
            # console.print(f"Skipping font formatting for row {row_no} and column {col}", style="bold yellow")
            pass
        i+=1
    return

def calculate_cagr(first_value: float, last_value: float, num_quarters: int) -> float:
    """
    Calculate annualized CAGR using the formula: ((Last Quarter Value / First Quarter Value)^(4/N)) - 1
    where N = number of quarter periods between first and last
    The formula is annualized by multiplying the exponent by 4 (quarters per year)
    
    Args:
        first_value: Value from the oldest quarter (beginning period)
        last_value: Value from the newest quarter (ending period)
        num_quarters: Number of quarter periods between first and last (N-1 for N quarters)
        
    Returns:
        Annualized CAGR as a decimal (multiply by 100 for percentage)
    """
    if first_value == 0 or num_quarters == 0:
        return 0.0
    if last_value < 0 and first_value > 0:
        # Handle negative to positive transition
        return 0.0
    if first_value < 0 and last_value < 0:
        # Both negative, calculate absolute CAGR
        ratio = abs(last_value) / abs(first_value)
    else:
        ratio = last_value / first_value
    
    if ratio <= 0:
        return 0.0
    
    # Annualized CAGR: (ratio ^ (4 / num_quarters)) - 1
    # This annualizes the quarterly growth rate
    cagr = (ratio ** (4.0 / num_quarters)) - 1
    # console.print(f"first quarter : {first_value} last quarter : {last_value} num_quarters : {num_quarters}  CAGR: {cagr}  ", style="bold green")
    return cagr

def create_consolidated_excel(heading_data:dict,excel_file_name:str) -> None:
    # STEP [ 1 ] ----------------- create a workbook with the quarterly financials sheet-------------------------------------------------
    workbook = load_workbook(excel_file_name)
    workbook.create_sheet("Quarterly Financials")
    current_sheet = workbook["Quarterly Financials"]
    
    # Get all quarter columns and sort them (most recent first)
    all_quarters = [item for item in heading_data["Revenue"][0].keys() if item != "Company Name"]
    # Sort quarters: Q2'25, Q1'25, Q4'25, Q3'24, Q2'24, Q1'24, etc.
    def sort_quarter_key(q):
        # Handle format like "Q2 '25" or "Q2'25"
        q_clean = q.replace(" ", "")
        if "'" in q_clean:
            parts = q_clean.split("'")
            quarter = parts[0].strip()
            year = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            q_num = int(quarter[1]) if len(quarter) > 1 and quarter[1].isdigit() else 0
            return (-year, -q_num)  # Negative for descending (most recent first)
        return (0, 0)
    
    all_quarters_sorted = sorted(all_quarters, key=sort_quarter_key)
    quarter_columns = all_quarters_sorted  # Get all quarters
    console.print(f"Quarter columns: {quarter_columns}", style="bold green")

    # STEP [ 2 ] ----------------- Get companies list-------------------------------------------------
    companies = [item["Company Name"] for item in heading_data["Revenue"]]  # COMPANIES LIST ⭐⭐
    num_companies = len(companies)
    console.print(f"Companies: {companies}", style="bold green")

    # Define financial metrics and growth metrics
    financial_metrics = ["Revenue", "Op. EBITDA %", "Op. EBIT %", "Op. PBT", "PBT"]
    growth_metrics = ["Revenue Growth", "Op. EBITDA Growth (Bps)", "Op. EBIT Growth (Bps)", "Op. PBT growth", "PBT growth"]
    
    # Define styling
    yellow_fill = PatternFill(start_color="FFFF00", end_color="FFFF00", fill_type="solid")
    bold_font = Font(bold=True)
    thin_border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    center_alignment = Alignment(horizontal='center', vertical='center')
    
    # STEP [ 3 ] ----------------- TOP BLOCK: Financial Metrics-------------------------------------------------
    TOP_BLOCK_ROW_START = 2
    PRIMARY_HEADER_ROW = TOP_BLOCK_ROW_START
    SECONDARY_HEADER_ROW = PRIMARY_HEADER_ROW + 1
    DATA_START_ROW = SECONDARY_HEADER_ROW + 1
    
    # Write "Companies" header in column B
    current_sheet.cell(row=PRIMARY_HEADER_ROW, column=2).value = "Companies"
    current_sheet.cell(row=PRIMARY_HEADER_ROW, column=2).font = bold_font
    current_sheet.cell(row=PRIMARY_HEADER_ROW, column=2).border = thin_border
    current_sheet.cell(row=PRIMARY_HEADER_ROW, column=2).alignment = center_alignment
    
    # Write company names in column B
    for idx, company in enumerate(companies):
        row = DATA_START_ROW + idx
        cell = current_sheet.cell(row=row, column=2)
        cell.value = company
        cell.border = thin_border
        cell.alignment = Alignment(horizontal='left', vertical='center')
    
    # Write primary headers (merged cells) in row 2
    col = 3  # Start from column C
    for metric in financial_metrics:
        start_col = col
        # Merge cells for this metric (all quarters)
        end_col = start_col + len(quarter_columns) - 1
        current_sheet.merge_cells(start_row=PRIMARY_HEADER_ROW, start_column=start_col, 
                                  end_row=PRIMARY_HEADER_ROW, end_column=end_col)
        cell = current_sheet.cell(row=PRIMARY_HEADER_ROW, column=start_col)
        cell.value = metric
        cell.font = bold_font
        cell.fill = yellow_fill
        cell.alignment = center_alignment
        cell.border = thin_border
        
        # Write secondary headers (quarter names) in row 3
        for q_idx, quarter in enumerate(quarter_columns):
            q_col = start_col + q_idx
            q_cell = current_sheet.cell(row=SECONDARY_HEADER_ROW, column=q_col)
            q_cell.value = quarter
            q_cell.font = bold_font
            q_cell.alignment = center_alignment
            q_cell.border = thin_border
        
        # Add separator column with border
        sep_col = end_col + 1
        for row in range(PRIMARY_HEADER_ROW, DATA_START_ROW + num_companies):
            sep_cell = current_sheet.cell(row=row, column=sep_col)
            sep_cell.border = thin_border
        col = sep_col + 1
    
    # Calculate total columns for top block
    # 5 metrics × N quarters + 4 separators, plus column B
    total_top_cols = 2 + (5 * len(quarter_columns)) + 4  # Column B + 5 metrics × N quarters + 4 separators
    
    # Apply borders to header rows
    for row in [PRIMARY_HEADER_ROW, SECONDARY_HEADER_ROW]:
        for c in range(2, total_top_cols + 1):
            cell = current_sheet.cell(row=row, column=c)
            if cell.border is None or (hasattr(cell.border, 'left') and cell.border.left is None):
                cell.border = thin_border
    
    # Write data for each company
    for company_idx, company in enumerate(companies):
        data_row = DATA_START_ROW + company_idx
        col = 3
        
        for metric in financial_metrics:
            # Find company data
            company_data = None
            for item in heading_data[metric]:
                if item["Company Name"] == company:
                    company_data = item
                    break
            
            if company_data:
                for quarter in quarter_columns:
                    value = company_data.get(quarter, "")
                    cell = current_sheet.cell(row=data_row, column=col)
                    cell.value = value
                    cell.border = thin_border
                    if isinstance(value, (int, float)):
                        # cell.number_format = '#,##0'
                        cell.alignment = Alignment(horizontal='right', vertical='center')
                    elif isinstance(value, str) and '%' in value:
                        cell.alignment = Alignment(horizontal='center', vertical='center')
                    else:
                        cell.alignment = Alignment(horizontal='right', vertical='center')
                    col += 1
            else:
                # Fill empty cells
                for _ in quarter_columns:
                    cell = current_sheet.cell(row=data_row, column=col)
                    cell.border = thin_border
                    cell.alignment = Alignment(horizontal='right', vertical='center')
                    col += 1
            
            col += 1  # Separator column
    
    # Apply borders to company column
    for row in range(PRIMARY_HEADER_ROW, DATA_START_ROW + num_companies):
        cell = current_sheet.cell(row=row, column=2)
        cell.border = thin_border
    
    # STEP [ 4 ] ----------------- BOTTOM BLOCK: Growth Metrics-------------------------------------------------
    BOTTOM_BLOCK_ROW_START = DATA_START_ROW + num_companies + 3  # 3 blank rows between blocks
    BOTTOM_PRIMARY_HEADER_ROW = BOTTOM_BLOCK_ROW_START
    BOTTOM_SECONDARY_HEADER_ROW = BOTTOM_PRIMARY_HEADER_ROW + 1
    BOTTOM_DATA_START_ROW = BOTTOM_SECONDARY_HEADER_ROW + 1
    
    # Write "Companies" header in column B for bottom block
    current_sheet.cell(row=BOTTOM_PRIMARY_HEADER_ROW, column=2).value = "Companies"
    current_sheet.cell(row=BOTTOM_PRIMARY_HEADER_ROW, column=2).font = bold_font
    current_sheet.cell(row=BOTTOM_PRIMARY_HEADER_ROW, column=2).border = thin_border
    current_sheet.cell(row=BOTTOM_PRIMARY_HEADER_ROW, column=2).alignment = center_alignment
    
    # Write company names in column B for bottom block
    for idx, company in enumerate(companies):
        row = BOTTOM_DATA_START_ROW + idx
        cell = current_sheet.cell(row=row, column=2)
        cell.value = company
        cell.border = thin_border
        cell.alignment = Alignment(horizontal='left', vertical='center')
    
    # Write primary headers for growth metrics (N quarters + CAGR)
    col = 3
    for metric in growth_metrics:
        start_col = col
        end_col = start_col + len(quarter_columns)  # N quarters + 1 CAGR
        current_sheet.merge_cells(start_row=BOTTOM_PRIMARY_HEADER_ROW, start_column=start_col,
                                  end_row=BOTTOM_PRIMARY_HEADER_ROW, end_column=end_col)
        cell = current_sheet.cell(row=BOTTOM_PRIMARY_HEADER_ROW, column=start_col)
        cell.value = metric
        cell.font = bold_font
        cell.fill = yellow_fill
        cell.alignment = center_alignment
        cell.border = thin_border
        
        # Write secondary headers (N quarters + CAGR)
        for q_idx, quarter in enumerate(quarter_columns):
            q_col = start_col + q_idx
            q_cell = current_sheet.cell(row=BOTTOM_SECONDARY_HEADER_ROW, column=q_col)
            q_cell.value = quarter
            q_cell.font = bold_font
            q_cell.alignment = center_alignment
            q_cell.border = thin_border
        
        # Add CAGR header
        cagr_col = start_col + len(quarter_columns)
        cagr_cell = current_sheet.cell(row=BOTTOM_SECONDARY_HEADER_ROW, column=cagr_col)
        cagr_cell.value = "CAGR"
        cagr_cell.font = bold_font
        cagr_cell.alignment = center_alignment
        cagr_cell.border = thin_border
        
        # Add separator column with border
        sep_col = end_col + 1
        for row in range(BOTTOM_PRIMARY_HEADER_ROW, BOTTOM_DATA_START_ROW + num_companies):
            sep_cell = current_sheet.cell(row=row, column=sep_col)
            sep_cell.border = thin_border
        col = sep_col + 1
    
    # Calculate total columns for bottom block
    # 5 metrics × (N quarters + CAGR) + 4 separators, plus column B
    total_bottom_cols = 2 + (5 * (len(quarter_columns) + 1)) + 4  # Column B + 5 metrics × (N quarters + 1) + 4 separators
    
    # Apply borders to bottom header rows
    for row in [BOTTOM_PRIMARY_HEADER_ROW, BOTTOM_SECONDARY_HEADER_ROW]:
        for c in range(2, total_bottom_cols + 1):
            cell = current_sheet.cell(row=row, column=c)
            if cell.border is None or (hasattr(cell.border, 'left') and cell.border.left is None):
                cell.border = thin_border
    
    # Write growth data for each company
    for company_idx, company in enumerate(companies):
        data_row = BOTTOM_DATA_START_ROW + company_idx
        col = 3
        
        for metric in growth_metrics:
            # Map growth metric names to heading_data keys
            metric_key = None
            if metric == "Revenue Growth":
                metric_key = "Revenue Growth Rate"
            elif metric == "Op. EBITDA Growth (Bps)":
                # Try different possible key names
                for key in heading_data.keys():
                    if "EBITDA" in key and "Growth" in key:
                        metric_key = key
                        break
            elif metric == "Op. EBIT Growth (Bps)":
                for key in heading_data.keys():
                    if "EBIT" in key and "Growth" in key and "EBITDA" not in key:
                        metric_key = key
                        break
            elif metric == "Op. PBT growth":
                for key in heading_data.keys():
                    if "PBT" in key and "growth" in key.lower() and "Op" in key:
                        metric_key = key
                        break
            elif metric == "PBT growth":
                for key in heading_data.keys():
                    if "PBT" in key and "growth" in key.lower() and "Op" not in key:
                        metric_key = key
                        break
            
            company_data = None
            if metric_key and metric_key in heading_data:
                for item in heading_data[metric_key]:
                    if item.get("Company Name") == company:
                        company_data = item
                        break
            
            if company_data:
                # Write quarter data
                for quarter in quarter_columns:
                    value = company_data.get(quarter, "")
                    cell = current_sheet.cell(row=data_row, column=col)
                    cell.value = value
                    cell.border = thin_border
                    if isinstance(value, str) and ('%' in value or value.replace('.', '').replace('-', '').isdigit()):
                        cell.alignment = Alignment(horizontal='center', vertical='center')
                    else:
                        cell.alignment = Alignment(horizontal='right', vertical='center')
                    col += 1
                
                # Calculate and write CAGR
                # Map growth metric to base metric for CAGR calculation
                base_metric_key = None
                if metric == "Revenue Growth":
                    base_metric_key = "Revenue"
                elif metric == "Op. EBITDA Growth (Bps)":
                    base_metric_key = "Op. EBITDA %"
                elif metric == "Op. EBIT Growth (Bps)":
                    base_metric_key = "Op. EBIT %"
                elif metric == "Op. PBT growth":
                    base_metric_key = "Op. PBT"
                elif metric == "PBT growth":
                    base_metric_key = "PBT"
                
                cagr_value = ""
                if base_metric_key and base_metric_key in heading_data and len(quarter_columns) > 1:
                    # Find company's base metric data
                    base_company_data = None
                    for item in heading_data[base_metric_key]:
                        if item.get("Company Name") == company:
                            base_company_data = item
                            break
                    
                    if base_company_data:
                        # Get first and last quarter values (quarters are sorted most recent first)
                        last_quarter = quarter_columns[0]  # Most recent
                        first_quarter = quarter_columns[-1]  # Oldest
                        
                        first_value = base_company_data.get(first_quarter)
                        last_value = base_company_data.get(last_quarter)
                        
                        # Convert to float if needed
                        if first_value is not None and last_value is not None:
                            try:
                                if isinstance(first_value, str):
                                    first_value = float(first_value.replace(",", "").replace("%", ""))
                                if isinstance(last_value, str):
                                    last_value = float(last_value.replace(",", "").replace("%", ""))
                                
                                num_quarters = len(quarter_columns) - 1  # Number of periods between first and last
                                if num_quarters > 0:
                                    cagr_decimal = calculate_cagr(first_value, last_value, num_quarters)
                                    cagr_value = str(round(cagr_decimal * 100, 3)) + "%"
                            except (ValueError, TypeError):
                                # If conversion fails, leave CAGR empty
                                pass
                
                cell = current_sheet.cell(row=data_row, column=col)
                cell.value = cagr_value
                cell.border = thin_border
                cell.alignment = Alignment(horizontal='center', vertical='center')
                col += 1
            else:
                # Fill empty cells
                for _ in range(len(quarter_columns) + 1):  # N quarters + CAGR
                    cell = current_sheet.cell(row=data_row, column=col)
                    cell.border = thin_border
                    cell.alignment = Alignment(horizontal='center', vertical='center')
                    col += 1
            
            col += 1  # Separator column
    
    # Apply borders to bottom company column
    for row in range(BOTTOM_PRIMARY_HEADER_ROW, BOTTOM_DATA_START_ROW + num_companies):
        cell = current_sheet.cell(row=row, column=2)
        cell.border = thin_border
    
    workbook.save(excel_file_name)
    
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

def main(companies:dict[str,str]) -> None:
    try:
        # STEP [ 1 ] ----------------- Get selected companies from user input -------------------------------------------------
        console.print("\n[bold cyan]Available Companies:[/bold cyan]")
        company_list = list(companies.keys())
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("No.", style="dim", width=6)
        table.add_column("Company Name", style="cyan")
        
        for idx, company_name in enumerate(company_list, 1):
            table.add_row(str(idx), company_name)
        
        console.print(table)
        console.print("\n[bold yellow]Enter company numbers to scrape (comma-separated, e.g., 1,3,5 or 'all' for all companies):[/bold yellow]")
        
        selection = Prompt.ask("Selection", default="all").strip().lower()
        
        selected_companies = {}
        if selection == "all":
            selected_companies = companies.copy()
        else:
            try:
                indices = [int(x.strip()) for x in selection.split(",")]
                for idx in indices:
                    if 1 <= idx <= len(company_list):
                        company_name = company_list[idx - 1]
                        selected_companies[company_name] = companies[company_name]
                    else:
                        console.print(f"[bold red]Warning: Invalid index {idx}, skipping[/bold red]")
                
                if not selected_companies:
                    console.print("[bold red]No valid companies selected. Exiting.[/bold red]")
                    return
            except ValueError:
                console.print("[bold red]Invalid input. Please enter numbers separated by commas or 'all'.[/bold red]")
                return
        
        console.print(f"\n[bold green]Selected {len(selected_companies)} company/companies: {', '.join(selected_companies.keys())}[/bold green]")
        
        # STEP [ 2 ] ----------------- Get output file path for consolidated data -------------------------------------------------
        console.print("\n[bold cyan]Enter output file path for consolidated data (Excel file):[/bold cyan]")
        console.print("[dim]Example: C:\\Users\\HP\\Desktop\\consolidated_data.xlsx or just 'consolidated_data.xlsx' for current directory[/dim]")
        file_name = Prompt.ask("Consolidated file path", default="Consolidated_quarterly_financials.xlsx")
        
        companies_df= []
        consolidated_data = {
            "Revenue" : [],
            "Op. EBITDA %" : [],
            "Op. EBIT %" : [],
            "Op. PBT" : [],
            "PBT" : [],
        }
        
        for company_name, url in selected_companies.items():
            console.print(f"\n[bold blue]Scraping data for {company_name}...[/bold blue]")
            # Scrape the quarterly financials
            quarterly_data = scrape_quarterly_financials(url, headless=True)
            result_from_parse = parse_data(quarterly_data,company_name)
            company_df = create_company_dataframe(result_from_parse[0],company_name,save_checkpoint=False)
            companies_df.append((company_name,company_df))
            consolidated_data["Revenue"].append(result_from_parse[1]["Revenue"])
            consolidated_data["Op. EBITDA %"].append(result_from_parse[1]["Op. EBITDA %"])
            consolidated_data["Op. EBIT %"].append(result_from_parse[1]["Op. EBIT %"])
            consolidated_data["Op. PBT"].append(result_from_parse[1]["Op. PBT"])
            consolidated_data["PBT"].append(result_from_parse[1]["PBT"])
        
        consolidated_data = add_more_headings(consolidated_data)
        
        save_companies_to_excel(companies_df, file_name)
        create_consolidated_excel(consolidated_data, file_name)
        
        console.print(f"\n[bold green]✓ Successfully created consolidated file: {file_name}[/bold green]")
        console.print(f"[bold green]✓ Successfully created companies file: {file_name}[/bold green]")
        
    except Exception as e:
        console.print(f"\n[bold red]Scraping failed: {e} , try again later[/bold red]")
        raise


if __name__ == "__main__":
    
    main(companies)

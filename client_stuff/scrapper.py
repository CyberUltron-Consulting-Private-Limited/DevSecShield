from openpyxl.worksheet import worksheet
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
def parse_data(dict_data:list[dict] , company_name:str) -> dict:


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
            total_income_from_operations = convert_values_to_int(item)
        if item["Indicators"] == "Purchase of Traded Goods" :
            purchase_of_traded_goods = convert_values_to_int(item)
        if item["Indicators"] == "Increase/Decrease in Stocks" :
            increase_decrease_in_stocks = convert_values_to_int(item)
        if item["Indicators"] == "Employees Cost" :
            employee_cost = convert_values_to_int(item)
        if item["Indicators"] == "Other Expenses" :
            other_expenses = convert_values_to_int(item)
        if item["Indicators"] == "Depreciation" :
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
    last_seen = total_income_from_operations[list(total_income_from_operations.keys())[-1]]
    for key in reversed(list(total_income_from_operations.keys())):
        if key == "Indicators":
            op_revenue_growth_rate["Indicators"] = "Operating Revenue Growth Rate"
            continue
        op_revenue_growth_rate[key] = str(round((last_seen - total_income_from_operations[key]) / last_seen * 100 , 2)) + "%"
        last_seen = total_income_from_operations[key]
    # console.print(f"Operating Revenue Growth Rate calculated successfully", style="bold green")
    result.append(op_revenue_growth_rate)


    # for contribution calculation
    contribution = {}
    for key in total_income_from_operations.keys():
        if key == "Indicators":
            contribution["Indicators"] = "Contribution"
            continue
        contribution[key] = total_income_from_operations[key] - purchase_of_traded_goods[key] - increase_decrease_in_stocks[key]
    # console.print(f"Contribution calculated successfully", style="bold green")
    result.append(contribution)

    
    # for op. ebitda calculation
    op_ebitda = {}
    for key in employee_cost.keys():
        if key == "Indicators":
            op_ebitda["Indicators"] = "Op. EBITDA"
            continue
        op_ebitda[key] = contribution[key] - employee_cost[key] - other_expenses[key]
    # console.print(f"Op. EBITDA calculated successfully", style="bold green")
    result.append(op_ebitda)

    # for op. ebit calculation
    op_ebit = {}
    for key in depreciation.keys():
        if key == "Indicators":
            op_ebit["Indicators"] = "Op. EBIT"
            continue
        op_ebit[key] = op_ebitda[key] - depreciation[key]
    # console.print(f"Op. EBIT calculated successfully", style="bold green")
    result.append(op_ebit)

    # for op. pbt calculation
    op_pbt = {}
    for key in interest.keys():
        if key == "Indicators":
            op_pbt["Indicators"] = "Op. PBT"
            continue
        op_pbt[key] = op_ebit[key] - interest[key]
    # console.print(f"Op. PBT calculated successfully", style="bold green")
    result.append(op_pbt)

    # for pbt calculation
    pbt = {}
    for key in other_income.keys():
        if key == "Indicators":
            pbt["Indicators"] = "PBT"
            continue
        pbt[key] = op_pbt[key] + other_income[key]
    # console.print(f"PBT calculated successfully", style="bold green")
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
        contribution_percentage[key] = str(round((contribution[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"Contribution % calculated successfully", style="bold green")
    result.append(contribution_percentage)

    # for employees cost % calculation
    employees_cost_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            employees_cost_percentage["Indicators"] = "Employees Cost %"
            continue
        employees_cost_percentage[key] = str(round((employee_cost[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"Employees Cost % calculated successfully", style="bold green")
    result.append(employees_cost_percentage)

    # for Other expenses % calculation
    other_expenses_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            other_expenses_percentage["Indicators"] = "Other Expenses %"
            continue
        other_expenses_percentage[key] = str(round((other_expenses[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"Other Expenses % calculated successfully", style="bold green")
    result.append(other_expenses_percentage)

    # for Op. EBITDA % calculation
    op_ebitda_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            op_ebitda_percentage["Indicators"] = "Op. EBITDA %"
            continue
        op_ebitda_percentage[key] = str(round((op_ebitda[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"Op. EBITDA % calculated successfully", style="bold green")
    result.append(op_ebitda_percentage)


    # for Op. EBIT % calculation
    op_ebit_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            op_ebit_percentage["Indicators"] = "Op. EBIT %"
            continue
        op_ebit_percentage[key] = str(round((op_ebit[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"Op. EBIT % calculated successfully", style="bold green")
    result.append(op_ebit_percentage)

    # for Op. PBT % calculation
    op_pbt_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            op_pbt_percentage["Indicators"] = "Op. PBT %"
            continue
        op_pbt_percentage[key] = str(round((op_pbt[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"Op. PBT % calculated successfully", style="bold green")
    result.append(op_pbt_percentage)

    # for PBT % calculation
    pbt_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            pbt_percentage["Indicators"] = "PBT %"
            continue
        pbt_percentage[key] = str(round((pbt[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"PBT % calculated successfully", style="bold green")
    result.append(pbt_percentage)

    # for Depreciation % calculation
    depreciation_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            depreciation_percentage["Indicators"] = "Depreciation %"
            continue
        depreciation_percentage[key] = str(round((depreciation[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"Depreciation % calculated successfully", style="bold green")
    result.append(depreciation_percentage)

    # for Interest % calculation
    interest_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            interest_percentage["Indicators"] = "Finance Costs / Interest %"
            continue
        interest_percentage[key] = str(round((interest[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"Interest % calculated successfully", style="bold green")
    result.append(interest_percentage)
    
    # for other income % calculation
    other_income_percentage = {}
    for key in contribution.keys():
        if key == "Indicators":
            other_income_percentage["Indicators"] = "Other Income %"
            continue
        other_income_percentage[key] = str(round((other_income[key] / total_income_from_operations[key]) * 100, 2)) + "%"
    # console.print(f"Other Income % calculated successfully", style="bold green")
    result.append(other_income_percentage)
    
    
    
    console.print(f"Profitability metrics calculated successfully", style="bold green")
    return (result,{
        "Revenue" : prepare_for_quarterly_dataframe(total_income_from_operations,company_name),
        "Op. EBITDA %" : prepare_for_quarterly_dataframe(op_ebitda_percentage,company_name),
        "Op. EBIT %" : prepare_for_quarterly_dataframe(op_ebit_percentage,company_name),
        "Op. PBT" : prepare_for_quarterly_dataframe(op_pbt,company_name),
        "PBT" : prepare_for_quarterly_dataframe(pbt,company_name),
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
    console.print(f"Dataframe created with columns : {" ".join(list(df.columns))}", style="bold green")

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
        time.sleep(5)
        
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


def add_more_headings(heading_data:dict) -> dict:
    # adding revenue growth % 
    heading_data["Revenue Growth Rate"] = []
    revenue = heading_data["Revenue"]
    for company_data in revenue:
        new_company_data = { "Company Name" : company_data["Company Name"] }
        last_seen = company_data[list(company_data.keys())[-1]]
        for key in reversed(list(company_data.keys())):
            if key == "Company Name":
                continue
            if isinstance(company_data[key], str):
                value = int(company_data[key].replace(",", ""))
            else:
                value = company_data[key]
            new_company_data[key] = str(round((last_seen - value) / last_seen * 100, 2)) + "%"
            last_seen = value
        heading_data["Revenue Growth Rate"].append(new_company_data)
    
    
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

def create_excel_skeleton(heading_data:dict) -> None:
    # STEP [ 1 ] ----------------- create a workbook with the quarterly financials sheet-------------------------------------------------
    workbook = Workbook()
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
    quarter_columns = all_quarters_sorted[:6]  # Get only the 6 most recent quarters
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
        # Merge cells for this metric (6 quarters)
        end_col = start_col + 5
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
    # 5 metrics × 6 quarters + 4 separators = 34 columns, plus column B = 35 total columns
    total_top_cols = 2 + (5 * 6) + 4  # Column B + 5 metrics × 6 quarters + 4 separators
    
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
                        cell.number_format = '#,##0'
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
    
    # Write primary headers for growth metrics (7 columns: 6 quarters + CAGR)
    col = 3
    for metric in growth_metrics:
        start_col = col
        end_col = start_col + 6  # 6 quarters + 1 CAGR = 7 columns
        current_sheet.merge_cells(start_row=BOTTOM_PRIMARY_HEADER_ROW, start_column=start_col,
                                  end_row=BOTTOM_PRIMARY_HEADER_ROW, end_column=end_col)
        cell = current_sheet.cell(row=BOTTOM_PRIMARY_HEADER_ROW, column=start_col)
        cell.value = metric
        cell.font = bold_font
        cell.fill = yellow_fill
        cell.alignment = center_alignment
        cell.border = thin_border
        
        # Write secondary headers (6 quarters + CAGR)
        for q_idx, quarter in enumerate(quarter_columns):
            q_col = start_col + q_idx
            q_cell = current_sheet.cell(row=BOTTOM_SECONDARY_HEADER_ROW, column=q_col)
            q_cell.value = quarter
            q_cell.font = bold_font
            q_cell.alignment = center_alignment
            q_cell.border = thin_border
        
        # Add CAGR header
        cagr_col = start_col + 6
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
    # 5 metrics × 7 columns (6 quarters + CAGR) + 4 separators = 39 columns, plus column B = 40 total columns
    total_bottom_cols = 2 + (5 * 7) + 4  # Column B + 5 metrics × 7 columns + 4 separators
    
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
                # Write CAGR (empty for now, can be calculated later)
                cell = current_sheet.cell(row=data_row, column=col)
                cell.value = ""
                cell.border = thin_border
                cell.alignment = Alignment(horizontal='center', vertical='center')
                col += 1
            else:
                # Fill empty cells
                for _ in range(7):  # 6 quarters + CAGR
                    cell = current_sheet.cell(row=data_row, column=col)
                    cell.border = thin_border
                    cell.alignment = Alignment(horizontal='center', vertical='center')
                    col += 1
            
            col += 1  # Separator column
    
    # Apply borders to bottom company column
    for row in range(BOTTOM_PRIMARY_HEADER_ROW, BOTTOM_DATA_START_ROW + num_companies):
        cell = current_sheet.cell(row=row, column=2)
        cell.border = thin_border
    
    workbook.save("Formatted_quarterly_financials.xlsx")
    




if __name__ == "__main__":
    try:
        i=0
        for company_name, url in companies.items():
            if i == 5:
                break
            # Scrape the quarterly financials
            quarterly_data = scrape_quarterly_financials(url, headless=True)
            with open(f"{company_name}_quarterly_data.json", "w+") as f:
                json.dump(quarterly_data, f, indent=2)
            parsed_data = parse_data(quarterly_data,company_name)
            company_df = create_company_dataframe(parsed_data[0],company_name)
            heading_data["Revenue"].append(parsed_data[1]["Revenue"])
            heading_data["Op. EBITDA %"].append(parsed_data[1]["Op. EBITDA %"])
            heading_data["Op. EBIT %"].append(parsed_data[1]["Op. EBIT %"])
            heading_data["Op. PBT"].append(parsed_data[1]["Op. PBT"])
            heading_data["PBT"].append(parsed_data[1]["PBT"])
            
            i+=1

        
        heading_data = add_more_headings(heading_data)
        # for testing 
        with open("heading_data.json", "w+") as f:
            json.dump(heading_data, f, indent=2)

        # for testing
        # with open("heading_data.json", "r") as f:
        #     heading_data = json.load(f)
        
        create_excel_skeleton(heading_data)
        
    except Exception as e:
        console.print(f"\nScraping failed: {e} , try again later ", style="bold red")
        raise
    

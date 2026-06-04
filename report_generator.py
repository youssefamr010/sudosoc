import pandas as pd
import json
import os
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ReportGenerator")

class ReportGenerator:
    """
    Generates professional, color-coded Excel reports from IDS/IPS alerts.
    """
    def __init__(self, alert_file="ids_alerts.jsonl", output_dir="reports"):
        self.alert_file = alert_file
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self):
        """
        Reads the JSONL alert file and creates a formatted Excel report.
        """
        if not os.path.exists(self.alert_file):
            logger.error(f"Alert file not found: {self.alert_file}")
            return

        logger.info(f"Generating report from {self.alert_file}...")
        
        alerts = []
        with open(self.alert_file, "r") as f:
            for line in f:
                try:
                    alerts.append(json.loads(line))
                except:
                    continue

        if not alerts:
            logger.warning("No alerts found to report.")
            return

        df = pd.DataFrame(alerts)
        
        # Format timestamp
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')

        # Generate filename
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f"security_audit_report_{timestamp_str}.xlsx")

        # Create Excel writer with xlsxwriter engine
        writer = pd.ExcelWriter(report_path, engine='xlsxwriter')
        df.to_excel(writer, index=False, sheet_name='Alerts')

        # Formatting
        workbook = writer.book
        worksheet = writer.sheets['Alerts']

        # Header format
        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'valign': 'top',
            'fg_color': '#D7E4BC',
            'border': 1
        })

        # Apply header format
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)

        # Conditional formatting for "Action" column
        # BLOCK = Red, ALERT = Yellow, ALLOW = Green
        if 'action' in df.columns:
            action_col_idx = df.columns.get_loc('action')
            
            # Red for BLOCK
            worksheet.conditional_format(1, action_col_idx, len(df), action_col_idx, {
                'type':     'cell',
                'criteria': '==',
                'value':    '"BLOCK"',
                'format':   workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
            })
            
            # Yellow for ALERT
            worksheet.conditional_format(1, action_col_idx, len(df), action_col_idx, {
                'type':     'cell',
                'criteria': '==',
                'value':    '"ALERT"',
                'format':   workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500'})
            })

            # Green for ALLOW
            worksheet.conditional_format(1, action_col_idx, len(df), action_col_idx, {
                'type':     'cell',
                'criteria': '==',
                'value':    '"ALLOW"',
                'format':   workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100'})
            })

        # Adjust column widths
        for i, col in enumerate(df.columns):
            max_len = max(df[col].astype(str).map(len).max(), len(col)) + 2
            worksheet.set_column(i, i, min(max_len, 50))

        # Add a summary sheet
        summary_data = {
            'Metric': ['Total Alerts', 'Blocked Attacks', 'Alerts Only', 'Trusted Agency Traffic'],
            'Count': [
                len(df),
                len(df[df['action'] == 'BLOCK']) if 'action' in df.columns else 0,
                len(df[df['action'] == 'ALERT']) if 'action' in df.columns else 0,
                len(df[df['label'] == 'TRUSTED_AGENCY']) if 'label' in df.columns else 0
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, index=False, sheet_name='Summary')
        
        # Summary chart
        summary_worksheet = writer.sheets['Summary']
        chart = workbook.add_chart({'type': 'pie'})
        chart.add_series({
            'name':       'Traffic Distribution',
            'categories': ['Summary', 1, 0, 3, 0],
            'values':     ['Summary', 1, 1, 3, 1],
            'points': [
                {'fill': {'color': '#FF0000'}}, # Blocked
                {'fill': {'color': '#FFFF00'}}, # Alerts
                {'fill': {'color': '#00FF00'}}, # Trusted
            ],
        })
        chart.set_title({'name': 'Security Event Distribution'})
        summary_worksheet.insert_chart('D2', chart)

        writer.close()
        logger.info(f"Report generated successfully: {report_path}")
        return report_path

if __name__ == "__main__":
    generator = ReportGenerator()
    generator.generate()

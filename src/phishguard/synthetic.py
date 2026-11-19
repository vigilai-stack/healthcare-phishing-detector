"""Fictional healthcare mail, both phishing and ordinary clinic messages.

Every link uses a reserved example domain. Attachment bodies are not created
here; only filenames and content types are stored. Nothing in this module
is a real patient, a real claim, or a working lure.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

from phishguard.parse import parsed_from_record, render_for_model, to_eml_bytes

N_VARIANTS = 10
SPLIT_BY_INDEX = {0: "train", 1: "train", 2: "train", 3: "val", 4: "test"}

FIRST = [
    "Alicia",
    "Ben",
    "Carmen",
    "Devon",
    "Elena",
    "Farid",
    "Grace",
    "Hiro",
    "Imani",
    "Jonah",
    "Keisha",
    "Luis",
    "Mei",
    "Nora",
    "Omar",
    "Priya",
]
LAST = [
    "Shah",
    "Nguyen",
    "Brooks",
    "Okeke",
    "Patel",
    "Garcia",
    "Chen",
    "Walker",
    "Diaz",
    "Hansen",
    "Cohen",
    "Rossi",
]
DATES = [
    "March 3, 2026",
    "March 18, 2026",
    "April 7, 2026",
    "April 22, 2026",
    "May 11, 2026",
    "June 2, 2026",
    "June 19, 2026",
    "July 8, 2026",
    "August 14, 2026",
    "September 9, 2026",
]
AMOUNTS = [
    "$42.15",
    "$86.00",
    "$128.40",
    "$214.90",
    "$305.00",
    "$476.25",
    "$640.10",
    "$812.00",
    "$1,026.55",
    "$1,480.00",
]


def _templates() -> list[dict]:
    rows: list[dict] = []

    def add(theme: str, label: int, index: int, **fields) -> None:
        rows.append(
            {
                "theme": theme,
                "label": label,
                "index": index,
                "demo": bool(fields.pop("demo", False)),
                **fields,
            }
        )

    # --- Explanation of benefits ---
    add(
        "eob",
        0,
        0,
        subject="Explanation of benefits posted for claim {claim}",
        from_header="Lumen Health Plan <notices@lumenhealthplan.example>",
        reply_to="notices@lumenhealthplan.example",
        body=(
            "Hello {patient},\n\n"
            "An explanation of benefits for claim {claim} was posted on {date}. "
            "The plan's share of the allowed amount is {amount}. This is not a bill. "
            "You can read the EOB at https://member.lumenhealthplan.example/claims/{claim}.\n\n"
            "If something on it looks wrong, call the number on your member card. "
            "That number is also listed as {phone} for this fictional plan.\n\n"
            "Lumen Health Plan member services"
        ),
    )
    add(
        "eob",
        0,
        1,
        subject="Paper EOB copy for {claim}",
        from_header="Lumen Health Plan <documents@lumenhealthplan.example>",
        reply_to="documents@lumenhealthplan.example",
        attachments=[{"filename": "EOB_{claim}.pdf", "content_type": "application/pdf"}],
        body=(
            "Hello {patient},\n\n"
            "The attached PDF is a copy of the explanation of benefits for claim {claim}, "
            "dated {date}. The figure {amount} is the amount the plan shows as patient "
            "responsibility. This is not a bill, and we are not asking you to pay from this email.\n\n"
            "The same document is on https://member.lumenhealthplan.example/claims/{claim}. "
            "Questions go to the phone number on your card ({phone}).\n\n"
            "Lumen Health Plan"
        ),
    )
    add(
        "eob",
        0,
        2,
        subject="Staff note: claim {claim} EOB is in the workqueue",
        from_header="{staff} <{staff_addr}>",
        reply_to="{staff_addr}",
        body=(
            "Team,\n\n"
            "Claim {claim} for {patient} (MRN {mrn}) has an EOB in the billing workqueue "
            "as of {date}. Patient responsibility shows {amount}. No letter needs to go out "
            "today. The payer file matches what we posted.\n\n"
            "I will call the patient only if the remittance is still missing on Friday. "
            "Use the clinic line {phone}, not a number from a payer email.\n\n"
            "{staff}\nNorthwind Community Clinic billing"
        ),
    )
    add(
        "eob",
        0,
        3,
        subject="How to read the EOB for claim {claim}",
        from_header="Northwind Community Clinic <billing@northwindclinic.example>",
        reply_to="billing@northwindclinic.example",
        body=(
            "Hello {patient},\n\n"
            "Your visit on {date} produced claim {claim}. Lumen Health Plan has posted the "
            "explanation of benefits. The clinic balance we show is {amount}. "
            "You do not need to send a payment because of this message.\n\n"
            "The EOB is available if you sign in through the member site you already use: "
            "https://member.lumenhealthplan.example/claims/{claim}. "
            "If you would rather not use the site, call us at {phone} and ask for billing.\n\n"
            "Northwind Community Clinic"
        ),
    )
    add(
        "eob",
        0,
        4,
        demo=True,
        subject="Your EOB for claim {claim} is ready",
        from_header="Lumen Health Plan <notices@lumenhealthplan.example>",
        reply_to="notices@lumenhealthplan.example",
        body=(
            "Hello {patient},\n\n"
            "Claim {claim} now has an explanation of benefits, posted {date}. "
            "This is not a bill. The plan lists {amount} in the patient-responsibility field.\n\n"
            "Read it here: https://member.lumenhealthplan.example/claims/{claim}\n\n"
            "If you have a question, use the phone number on your member card. "
            "For this fictional plan that number is {phone}.\n\n"
            "Lumen Health Plan"
        ),
    )
    add(
        "eob",
        1,
        0,
        subject="Claim {claim} denied — appeal before coverage lapses",
        from_header="Lumen Health Plan Alerts <alerts@lumenhealthplan.secure-login.example>",
        reply_to="appeals@gmail.com",
        body=(
            "Hello {patient},\n\n"
            "Claim {claim} was denied on {date}. The full amount {amount} will be billed "
            "to you unless you appeal immediately. Failure to respond within 4 hours will "
            "close the appeal window and your account will be suspended.\n\n"
            "Verify your identity and upload the appeal here: "
            "https://lumenhealthplan.secure-login.example/appeal/{claim}\n\n"
            "Do not ignore this notice.\n\n"
            "Lumen Appeals Desk"
        ),
    )
    add(
        "eob",
        1,
        1,
        subject="EOB locked for claim {claim}",
        from_header="Lumen Health Plan <member.services@1umenhealthplan.example>",
        reply_to="member.services@1umenhealthplan.example",
        body=(
            "Dear {patient},\n\n"
            "We could not deliver the explanation of benefits for claim {claim} ({amount}, {date}) "
            "because your mailbox must be confirmed. Confirm your account right away or the "
            "record will be deleted.\n\n"
            "Open https://member.1umenhealthplan.example/unlock/{claim} and sign in.\n\n"
            "Lumen Health Plan"
        ),
    )
    add(
        "eob",
        1,
        2,
        subject="Final notice: patient responsibility {amount}",
        from_header="Lumen Health Plan Billing <billing@lumenhealthplan-pay.example>",
        reply_to="billing@lumenhealthplan-pay.example",
        attachments=[{"filename": "EOB_{claim}.html", "content_type": "text/html"}],
        body=(
            "Hello {patient},\n\n"
            "This is a final notice for claim {claim}. The unpaid patient share is {amount}. "
            "Open the attached EOB page and pay within 2 hours to avoid a service hold. "
            "Act now so the balance is not sent to collections.\n\n"
            "If the attachment asks you to sign in, that is required before the receipt will show.\n\n"
            "Lumen Collections"
        ),
    )
    add(
        "eob",
        1,
        3,
        subject="Updated banking for your claim refund {claim}",
        from_header="Lumen Health Plan <refunds@lumenhealthplan.example>",
        reply_to="refunds.desk@gmail.com",
        body=(
            "Hello {patient},\n\n"
            "A refund of {amount} on claim {claim} cannot be sent until you confirm your banking. "
            "The previous direct deposit failed. Reply with the updated bank account and routing "
            "number today, or the refund will be cancelled.\n\n"
            "This mailbox is monitored immediately.\n\n"
            "Lumen Refunds"
        ),
    )
    add(
        "eob",
        1,
        4,
        demo=True,
        subject="Action required: claim {claim} will be billed in full",
        from_header="Lumen Health Plan <alerts@member.lumenhealthplan.example>",
        reply_to="alerts@gmail.com",
        links=[
            {
                "href": "https://member.1umenhealthplan.example/appeal/{claim}",
                "text": "https://member.lumenhealthplan.example/appeal/{claim}",
            }
        ],
        body=(
            "Hello {patient},\n\n"
            "Your explanation of benefits for claim {claim} shows a denial. "
            "The full amount {amount} will be billed unless you appeal immediately, today {date}.\n\n"
            "Use this secure link to verify your identity and file the appeal:\n"
            "https://member.lumenhealthplan.example/appeal/{claim}\n\n"
            "Failure to respond within 2 hours will lock the claim. Do not ignore this message.\n\n"
            "Lumen Health Plan member security"
        ),
    )

    # --- Lab results ---
    add(
        "lab",
        0,
        0,
        subject="Lab results are posted",
        from_header="Cedar Lab Partners <results@cedarlabpartners.example>",
        reply_to="results@cedarlabpartners.example",
        body=(
            "Hello {patient},\n\n"
            "Results from your draw on {date} are posted for MRN {mrn}. "
            "This message does not say whether the result is normal. "
            "Read the report at https://results.cedarlabpartners.example/mrn/{mrn}.\n\n"
            "Cedar Lab will not ask you to email a password. If you cannot get in, "
            "call the lab at {phone} and have the order number {claim} ready.\n\n"
            "Cedar Lab Partners"
        ),
    )
    add(
        "lab",
        0,
        1,
        subject="Copy of lab report {claim}",
        from_header="Cedar Lab Partners <records@cedarlabpartners.example>",
        reply_to="records@cedarlabpartners.example",
        attachments=[{"filename": "Lab_{mrn}.pdf", "content_type": "application/pdf"}],
        body=(
            "Hello {patient},\n\n"
            "The attached PDF is the lab report for order {claim}, collected {date}. "
            "Your clinician at Northwind also has a copy. Please discuss the result with "
            "them. The file is the same one posted at "
            "https://results.cedarlabpartners.example/orders/{claim}.\n\n"
            "Records desk, {phone}"
        ),
    )
    add(
        "lab",
        0,
        2,
        subject="Result arrived for {patient}",
        from_header="{staff} <{staff_lab}>",
        reply_to="{staff_lab}",
        body=(
            "Nursing team,\n\n"
            "Cedar posted results for {patient}, MRN {mrn}, order {claim}, on {date}. "
            "I filed them on the chart. No patient call is scheduled unless the covering "
            "clinician asks for one. The patient was told at check-out to expect a portal "
            "note, not a download from an outside address.\n\n"
            "{staff}"
        ),
    )
    add(
        "lab",
        0,
        3,
        subject="Your Northwind lab from {date}",
        from_header="Northwind Community Clinic <portal@northwindclinic.example>",
        reply_to="portal@northwindclinic.example",
        body=(
            "Hello {patient},\n\n"
            "The lab from your visit on {date} (order {claim}) is on the clinic portal: "
            "https://portal.northwindclinic.example/results/{mrn}. "
            "We do not include the numbers in email.\n\n"
            "Call {phone} if you cannot see the visit. Bring MRN {mrn} if you call.\n\n"
            "Northwind Community Clinic"
        ),
    )
    add(
        "lab",
        0,
        4,
        subject="Lab report ready for order {claim}",
        from_header="Cedar Lab Partners <results@cedarlabpartners.example>",
        reply_to="results@cedarlabpartners.example",
        body=(
            "Hello {patient},\n\n"
            "Order {claim} from {date} is complete. The report is on "
            "https://results.cedarlabpartners.example/orders/{claim}. "
            "MRN on the order is {mrn}.\n\n"
            "Please review it with your clinician. The lab phone is {phone}.\n\n"
            "Cedar Lab Partners"
        ),
    )
    add(
        "lab",
        1,
        0,
        subject="Abnormal lab — verify within 2 hours",
        from_header="Cedar Lab Partners <alerts@cedarlab-partners.example>",
        reply_to="alerts@cedarlab-partners.example",
        body=(
            "Hello {patient},\n\n"
            "An abnormal result for order {claim} (MRN {mrn}) is being held. "
            "Verify your identity within 2 hours or the record will be deleted and "
            "your account will be locked.\n\n"
            "Open https://results.cedarlab-partners.example/critical/{claim} immediately "
            "and sign in. Do not ignore this alert.\n\n"
            "Cedar Lab Critical Desk"
        ),
    )
    add(
        "lab",
        1,
        1,
        subject="Encrypted lab file for {patient}",
        from_header="Cedar Lab Results <results@gmail.com>",
        reply_to="results@gmail.com",
        attachments=[{"filename": "CRITICAL_{claim}.html", "content_type": "text/html"}],
        body=(
            "Hello {patient},\n\n"
            "Your lab from {date} is abnormal. The full report is the attached web page. "
            "Open it right away and enter your password so the values will display. "
            "Failure to respond today means the ordering clinic will not receive a copy.\n\n"
            "Cedar Lab Partners results team"
        ),
    )
    add(
        "lab",
        1,
        2,
        subject="Results password reset for MRN {mrn}",
        from_header="Cedar Lab Partners <noreply@cedar1abpartners.example>",
        reply_to="noreply@cedar1abpartners.example",
        body=(
            "Hello {patient},\n\n"
            "Someone asked to reset the password on the lab portal for MRN {mrn}. "
            "If you do not confirm within 30 minutes the account will be suspended.\n\n"
            "Confirm your identity: https://portal.cedar1abpartners.example/reset/{mrn}\n\n"
            "Cedar Lab security"
        ),
    )
    add(
        "lab",
        1,
        3,
        subject="Lab invoice {invoice} is past due",
        from_header="Cedar Lab Billing <billing@cedarlabpartners.example>",
        reply_to="billing-help@outlook.com",
        body=(
            "Hello {patient},\n\n"
            "Lab order {claim} has a past due balance of {amount}. "
            "Pay immediately with a wire transfer, or reply with the updated bank account "
            "so we can debit it. Act now to avoid a service hold on future draws.\n\n"
            "A receipt will be sent after you confirm your banking.\n\n"
            "Cedar Lab billing"
        ),
    )
    add(
        "lab",
        1,
        4,
        subject="New lab message for order {claim}",
        from_header="Cedar Lab Partners <results@results.cedarlabpartners.example>",
        reply_to="lab.desk@gmail.com",
        body=(
            "Hello {patient},\n\n"
            "A new result was added on {date} for order {claim}. "
            "Please review it when you can. The ordering clinic was Northwind.\n\n"
            "If you want a copy by email, reply to this message and include your date of birth.\n\n"
            "Cedar Lab Partners"
        ),
    )

    # --- EHR / password ---
    add(
        "ehr",
        0,
        0,
        subject="Halcyon password reset request",
        from_header="Halcyon EHR <noreply@halcyonehr.example>",
        reply_to="noreply@halcyonehr.example",
        body=(
            "Hello {staff},\n\n"
            "A password reset was requested for your Halcyon account on {date}. "
            "If this was you, continue at https://login.halcyonehr.example/reset. "
            "The page stops accepting this request after 2 hours.\n\n"
            "If this was not you, you can ignore the message. Your password will stay "
            "as it is. The help desk is {phone}.\n\n"
            "Halcyon EHR"
        ),
    )
    add(
        "ehr",
        0,
        1,
        subject="New result in the chart for {patient}",
        from_header="Halcyon EHR <notify@halcyonehr.example>",
        reply_to="notify@halcyonehr.example",
        body=(
            "Hello {staff},\n\n"
            "A result was filed for {patient}, MRN {mrn}, on {date}. "
            "Open the chart from the Halcyon icon on your clinic desktop, or go to "
            "https://login.halcyonehr.example/chart/{mrn} after you are already signed in "
            "on the clinic network.\n\n"
            "This note does not include the result.\n\n"
            "Halcyon EHR"
        ),
    )
    add(
        "ehr",
        0,
        2,
        subject="Your MyChart activation code",
        from_header="Northwind Community Clinic <portal@northwindclinic.example>",
        reply_to="portal@northwindclinic.example",
        body=(
            "Hello {patient},\n\n"
            "You asked the front desk on {date} for a MyChart activation code. "
            "The code is {claim}. Enter it at https://mychart.northwindclinic.example/activate. "
            "The code is for this fictional clinic portal only.\n\n"
            "If you did not ask for this, call {phone} and we will cancel it.\n\n"
            "Northwind Community Clinic"
        ),
    )
    add(
        "ehr",
        0,
        3,
        subject="Scheduled Halcyon downtime Saturday",
        from_header="Halcyon EHR <status@halcyonehr.example>",
        reply_to="status@halcyonehr.example",
        body=(
            "Clinic staff,\n\n"
            "Halcyon will be unavailable Saturday 1:00 a.m. to 3:00 a.m. for maintenance. "
            "Downtime packets are in the nursing station binder. You do not need to reset "
            "your password and you do not need to install anything.\n\n"
            "Status page: https://status.halcyonehr.example\n\n"
            "Help desk {phone}"
        ),
    )
    add(
        "ehr",
        0,
        4,
        subject="Halcyon account is active",
        from_header="Halcyon EHR <noreply@halcyonehr.example>",
        reply_to="noreply@halcyonehr.example",
        body=(
            "Hello {staff},\n\n"
            "Your Halcyon account was created on {date}. Sign-on uses the clinic network "
            "password you already have. The address is https://login.halcyonehr.example.\n\n"
            "No attachment is included. If a later message asks you to open a file to "
            "keep the account, call the help desk at {phone} instead.\n\n"
            "Halcyon EHR"
        ),
    )
    add(
        "ehr",
        1,
        0,
        subject="Halcyon password expires in 30 minutes",
        from_header="Halcyon EHR Security <security@halcyonehr.secure-login.example>",
        reply_to="security@halcyonehr.secure-login.example",
        body=(
            "Hello {staff},\n\n"
            "Your EHR password expires in 30 minutes. The account will be suspended and "
            "you will lose chart access. Reset it immediately:\n"
            "https://halcyonehr.secure-login.example/password/{claim}\n\n"
            "Verify your identity on that page. Failure to respond will lock the account.\n\n"
            "Halcyon security"
        ),
    )
    add(
        "ehr",
        1,
        1,
        subject="Multi-factor reset for Halcyon",
        from_header="Halcyon EHR <it-support@gmail.com>",
        reply_to="it-support@gmail.com",
        body=(
            "Hello {staff},\n\n"
            "IT is resetting multi-factor sign-in for the EHR tonight. Reply to this "
            "personal mailbox with your current password and the one-time code on your token "
            "so we can move the account. Do this right away or you will be locked out of "
            "tomorrow's clinic.\n\n"
            "Halcyon help desk"
        ),
    )
    add(
        "ehr",
        1,
        2,
        subject="Install the chart update",
        from_header="Halcyon EHR <updates@halcyonehr-reset.example>",
        reply_to="updates@halcyonehr-reset.example",
        attachments=[{"filename": "HalcyonUpdate.docm", "content_type": "application/vnd.ms-word.document.macroEnabled.12"}],
        body=(
            "Hello {staff},\n\n"
            "A required chart update is attached. Open the document and enable macros "
            "or your sign-in will fail on {date}. This takes about one minute.\n\n"
            "Act now so the morning session is not blocked.\n\n"
            "Halcyon desktop team"
        ),
    )
    add(
        "ehr",
        1,
        3,
        subject="Unusual sign-in on your EHR account",
        from_header="Halcyon EHR <noreply@ha1cyonehr.example>",
        reply_to="noreply@ha1cyonehr.example",
        body=(
            "Hello {staff},\n\n"
            "We saw a sign-in to your Halcyon account from a new device. "
            "Confirm your identity within 1 hour or the account will be locked.\n\n"
            "Review the session: https://login.ha1cyonehr.example/session/{claim}\n\n"
            "Halcyon security"
        ),
    )
    add(
        "ehr",
        1,
        4,
        subject="MyChart document for {patient}",
        from_header="Northwind MyChart <mychart@northwindclinic-alert.example>",
        reply_to="mychart@northwindclinic-alert.example",
        attachments=[{"filename": "Visit_summary.pdf.exe", "content_type": "application/octet-stream"}],
        body=(
            "Hello {patient},\n\n"
            "Your visit summary is attached. Open it to keep your MyChart account active. "
            "The file name looks like a PDF. If Windows asks for permission, allow it.\n\n"
            "Portal copy: https://mychart.northwindclinic-alert.example/visit/{mrn}\n\n"
            "Northwind MyChart"
        ),
    )

    # --- Payroll and benefits ---
    add(
        "payroll",
        0,
        0,
        subject="Open enrollment closes Friday",
        from_header="Marigold Benefits <benefits@marigoldbenefits.example>",
        reply_to="benefits@marigoldbenefits.example",
        body=(
            "Hello {staff},\n\n"
            "Open enrollment for next year closes Friday, October 16, 2026. "
            "Your current plan stays in place if you do nothing. "
            "Review choices at https://enroll.marigoldbenefits.example/elections.\n\n"
            "Human resources can walk through the form with you. The HR line is {phone}. "
            "We will not ask you to send a bank account number by email.\n\n"
            "Marigold Benefits"
        ),
    )
    add(
        "payroll",
        0,
        1,
        subject="Pay statement for the period ending {date}",
        from_header="Westbridge Payroll <payroll@westbridgemed.example>",
        reply_to="payroll@westbridgemed.example",
        attachments=[{"filename": "paystub_{invoice}.pdf", "content_type": "application/pdf"}],
        body=(
            "Hello {staff},\n\n"
            "The attached PDF is your pay statement for the period ending {date}. "
            "Net pay is {amount}. Direct deposit is unchanged.\n\n"
            "The same statement is at https://payroll.westbridgemed.example/statements/{invoice}. "
            "Questions go to payroll at {phone}.\n\n"
            "Westbridge Specialty payroll"
        ),
    )
    add(
        "payroll",
        0,
        2,
        subject="Benefits question from {staff}",
        from_header="{staff} <{staff_addr}>",
        reply_to="{staff_addr}",
        body=(
            "HR,\n\n"
            "Can someone confirm whether the dental election I entered on {date} saved? "
            "The Marigold page showed a confirmation number {claim}. I did not change "
            "direct deposit. I will stop by Thursday if I do not hear back.\n\n"
            "Thanks,\n{staff}"
        ),
    )
    add(
        "payroll",
        0,
        3,
        subject="W-2 copies are available",
        from_header="Westbridge Payroll <payroll@westbridgemed.example>",
        reply_to="payroll@westbridgemed.example",
        body=(
            "Hello {staff},\n\n"
            "Last year's W-2 is posted at https://payroll.westbridgemed.example/tax. "
            "We are not mailing a second copy unless you call {phone} and ask. "
            "Please do not send a Social Security number by reply email. "
            "We already have the number on your hire form.\n\n"
            "Westbridge payroll"
        ),
    )
    add(
        "payroll",
        0,
        4,
        subject="Enrollment reminder for {staff}",
        from_header="Marigold Benefits <benefits@marigoldbenefits.example>",
        reply_to="benefits@marigoldbenefits.example",
        body=(
            "Hello {staff},\n\n"
            "This is a reminder that open enrollment is open through October 16, 2026. "
            "Look at the plans here: https://enroll.marigoldbenefits.example/elections. "
            "If you skip it, your current coverage continues.\n\n"
            "HR phone: {phone}.\n\n"
            "Marigold Benefits"
        ),
    )
    add(
        "payroll",
        1,
        0,
        subject="Direct deposit failed — payroll will be delayed",
        from_header="Westbridge Payroll <payroll@westbridgemed.pay-update.example>",
        reply_to="payroll@westbridgemed.pay-update.example",
        body=(
            "Hello {staff},\n\n"
            "Direct deposit failed for the {date} payroll. Confirm your banking immediately "
            "or payroll will be delayed and the payment of {amount} will be returned.\n\n"
            "Update the account: https://westbridgemed.pay-update.example/dd/{invoice}\n\n"
            "Enter the routing number on that page. Act now.\n\n"
            "Westbridge payroll"
        ),
    )
    add(
        "payroll",
        1,
        1,
        subject="Benefits card replacement",
        from_header="Marigold Benefits Team <benefits.team@gmail.com>",
        reply_to="benefits.team@gmail.com",
        body=(
            "Hello {staff},\n\n"
            "Your medical benefits card was returned by the mail room. To ship a new one "
            "we need you to verify your identity. Reply with a photo of your driver's "
            "license and your employee password for the HR site.\n\n"
            "Please do this right away so coverage questions at the pharmacy do not pile up.\n\n"
            "Marigold Benefits team"
        ),
    )
    add(
        "payroll",
        1,
        2,
        subject="Final notice: enroll or lose the match",
        from_header="Marigold Benefits <enroll@marigoldbenefits-secure.example>",
        reply_to="enroll@marigoldbenefits-secure.example",
        body=(
            "Hello {staff},\n\n"
            "This is a final notice. Your retirement match will lapse tonight unless you "
            "confirm your account. Failure to respond means the {amount} match for this "
            "period is forfeited.\n\n"
            "Sign in immediately: https://enroll.marigoldbenefits-secure.example/match/{claim}\n\n"
            "Marigold Benefits"
        ),
    )
    add(
        "payroll",
        1,
        3,
        subject="Updated bank details for expense reimbursement",
        from_header="Westbridge Payroll <payroll@westbridgemed.example>",
        reply_to="reimburse@outlook.com",
        body=(
            "Hello {staff},\n\n"
            "Accounts payable changed banks. Send the updated bank account and routing "
            "number so your {amount} reimbursement from {date} is not lost. "
            "A wire transfer will go out only after you reply.\n\n"
            "Paste the numbers in the reply. Do it today.\n\n"
            "Westbridge payroll"
        ),
    )
    add(
        "payroll",
        1,
        4,
        subject="Payroll file you requested",
        from_header="Westbridge Payroll <payroll@westbridge-med.example>",
        reply_to="payroll@westbridge-med.example",
        attachments=[{"filename": "direct_deposit.xlsm", "content_type": "application/vnd.ms-excel.sheet.macroEnabled.12"}],
        body=(
            "Hello {staff},\n\n"
            "The payroll change form is attached. Enable macros so the direct deposit "
            "fields will calculate. Return it today if you want the change on the next file.\n\n"
            "Westbridge payroll"
        ),
    )

    # --- Vendor invoices ---
    add(
        "invoice",
        0,
        0,
        subject="Invoice {invoice} from Pike Street Billing",
        from_header="Pike Street Billing <ap@pikestreetbilling.example>",
        reply_to="ap@pikestreetbilling.example",
        attachments=[{"filename": "Invoice_{invoice}.pdf", "content_type": "application/pdf"}],
        body=(
            "Hello Northwind accounts payable,\n\n"
            "Invoice {invoice} dated {date} is attached. The total is {amount}. "
            "Please pay it through the portal you already use: "
            "https://pay.pikestreetbilling.example/invoices/{invoice}. "
            "Our bank details have not changed.\n\n"
            "Questions: {phone}.\n\n"
            "Pike Street Billing"
        ),
    )
    add(
        "invoice",
        0,
        1,
        subject="Statement for {invoice}",
        from_header="Pike Street Billing <statements@pikestreetbilling.example>",
        reply_to="statements@pikestreetbilling.example",
        body=(
            "Hello,\n\n"
            "This is the monthly statement for invoice {invoice}. Balance {amount} as of {date}. "
            "No payment is requested in this email. The statement matches the PDF in the portal "
            "at https://pay.pikestreetbilling.example/invoices/{invoice}.\n\n"
            "Pike Street Billing, {phone}"
        ),
    )
    add(
        "invoice",
        0,
        2,
        subject="Please code invoice {invoice}",
        from_header="{staff} <{staff_addr}>",
        reply_to="{staff_addr}",
        body=(
            "AP,\n\n"
            "Pike Street invoice {invoice} for {amount} looks like the monthly coding support "
            "retainer. I compared it with the March contract. Please pay it on the usual "
            "cycle. I do not see a bank-account change on their letterhead.\n\n"
            "{staff}\nNorthwind operations"
        ),
    )
    add(
        "invoice",
        0,
        3,
        subject="W-9 on file for Pike Street",
        from_header="Pike Street Billing <ap@pikestreetbilling.example>",
        reply_to="ap@pikestreetbilling.example",
        body=(
            "Hello,\n\n"
            "You asked for a W-9 on {date}. The one we already sent is still current. "
            "A copy is at https://pay.pikestreetbilling.example/vendors/w9. "
            "We are not changing where payments go.\n\n"
            "Accounts payable, {phone}"
        ),
    )
    add(
        "invoice",
        0,
        4,
        subject="Invoice {invoice} is ready to view",
        from_header="Pike Street Billing <ap@pikestreetbilling.example>",
        reply_to="ap@pikestreetbilling.example",
        body=(
            "Hello,\n\n"
            "Invoice {invoice} ({amount}, {date}) is ready. "
            "View it at https://pay.pikestreetbilling.example/invoices/{invoice}. "
            "Payment terms are the same as the last invoice. Bank details have not changed.\n\n"
            "Pike Street Billing"
        ),
    )
    add(
        "invoice",
        1,
        0,
        subject="Past due invoice {invoice} — remit today",
        from_header="Pike Street Billing <ap@pikestreetbilling-remit.example>",
        reply_to="ap@pikestreetbilling-remit.example",
        body=(
            "Hello Northwind accounts payable,\n\n"
            "Invoice {invoice} for {amount} is past due as of {date}. Remit today to avoid "
            "a service hold on coding support. Our bank details changed. The new routing "
            "number is on this page:\n"
            "https://pay.pikestreetbilling-remit.example/wire/{invoice}\n\n"
            "Act now. A wire transfer is preferred.\n\n"
            "Pike Street Billing"
        ),
    )
    add(
        "invoice",
        1,
        1,
        subject="Revised invoice {invoice}",
        from_header="Pike Street Accounts <accounts.payable@gmail.com>",
        reply_to="accounts.payable@gmail.com",
        attachments=[{"filename": "Invoice_{invoice}.html", "content_type": "text/html"}],
        body=(
            "Hello,\n\n"
            "The revised invoice {invoice} is the attached web page. Open it and confirm "
            "the updated bank account before you pay {amount}. The old account will be "
            "closed tonight.\n\n"
            "Please do this immediately so the payment is not returned.\n\n"
            "Pike Street accounts"
        ),
    )
    add(
        "invoice",
        1,
        2,
        subject="Payment portal password for invoice {invoice}",
        from_header="Pike Street Billing <ap@pikestreetbi11ing.example>",
        reply_to="ap@pikestreetbi11ing.example",
        body=(
            "Hello,\n\n"
            "Your vendor portal password must be reset before invoice {invoice} ({amount}) "
            "can be reconciled. The account will be locked if you do not verify your identity "
            "within 4 hours.\n\n"
            "Reset: https://pay.pikestreetbi11ing.example/reset/{invoice}\n\n"
            "Pike Street Billing"
        ),
    )
    add(
        "invoice",
        1,
        3,
        subject="Urgent: duplicate payment on {invoice}",
        from_header="Pike Street Billing <ap@pikestreetbilling.example>",
        reply_to="refunds@hotmail.com",
        body=(
            "Hello,\n\n"
            "We received a duplicate payment on invoice {invoice}. To return {amount} we need "
            "the updated bank account and routing number. Reply to this message right away. "
            "Failure to respond means the refund is forfeited.\n\n"
            "Pike Street treasury"
        ),
    )
    add(
        "invoice",
        1,
        4,
        subject="Invoice package {invoice}",
        from_header="Pike Street Billing <ap@pike-street-billing.example>",
        reply_to="ap@pike-street-billing.example",
        attachments=[{"filename": "invoice_{invoice}.zip", "content_type": "application/zip"}],
        body=(
            "Hello Northwind AP,\n\n"
            "The invoice package is zipped because it includes the new payment instructions. "
            "Unzip it and use the bank account inside, not the one from last month. "
            "Total due {amount}. Please remit today.\n\n"
            "Pike Street Billing"
        ),
    )

    # --- Fax and e-referral ---
    add(
        "referral",
        0,
        0,
        subject="Referral packet is in the queue",
        from_header="Riverbend Medical Group <referrals@riverbendmg.example>",
        reply_to="referrals@riverbendmg.example",
        body=(
            "Hello Northwind referrals,\n\n"
            "We received your referral for {patient}, MRN {mrn}, on {date}. "
            "The packet is in our workqueue under tracking number {claim}. "
            "You do not need to download anything. If a page is missing, call {phone} "
            "and ask for referrals.\n\n"
            "Status, if you want it: https://referrals.riverbendmg.example/track/{claim}\n\n"
            "Riverbend Medical Group"
        ),
    )
    add(
        "referral",
        0,
        1,
        subject="Records request completed",
        from_header="Northwind HIM <records@northwindclinic.example>",
        reply_to="records@northwindclinic.example",
        attachments=[{"filename": "Referral_{claim}.pdf", "content_type": "application/pdf"}],
        body=(
            "Hello,\n\n"
            "The attached PDF is the chart excerpt Riverbend requested for {patient} "
            "(MRN {mrn}). It was released under the authorization we have on file, dated {date}. "
            "Please file it with tracking number {claim}.\n\n"
            "Health information management, {phone}"
        ),
    )
    add(
        "referral",
        0,
        2,
        subject="Did the Westbridge packet arrive?",
        from_header="{staff} <{staff_addr}>",
        reply_to="{staff_addr}",
        body=(
            "Referrals,\n\n"
            "Westbridge said they faxed six pages for {patient} on {date}, tracking {claim}. "
            "I do not see it in the scan folder. Can someone check before noon? "
            "I will call their referrals line if it is not there. I am not expecting "
            "a link or a password from them.\n\n"
            "{staff}"
        ),
    )
    add(
        "referral",
        0,
        3,
        subject="e-referral received {claim}",
        from_header="Westbridge Specialty <referrals@westbridgemed.example>",
        reply_to="referrals@westbridgemed.example",
        body=(
            "Hello,\n\n"
            "Referral {claim} for {patient} is in the Westbridge queue as of {date}. "
            "The receiving clinician will review it this week. No further form is required "
            "unless we call you at the clinic number we already have.\n\n"
            "You can look at status on https://referrals.westbridgemed.example/r/{claim}.\n\n"
            "Westbridge Specialty referrals"
        ),
    )
    add(
        "referral",
        0,
        4,
        subject="Referral {claim} accepted",
        from_header="Riverbend Medical Group <referrals@riverbendmg.example>",
        reply_to="referrals@riverbendmg.example",
        body=(
            "Hello,\n\n"
            "Referral {claim} for {patient} (MRN {mrn}) was accepted on {date}. "
            "The patient will get a scheduling call from our main number. "
            "This email has no attachment on purpose.\n\n"
            "Riverbend referrals, {phone}"
        ),
    )
    add(
        "referral",
        1,
        0,
        subject="Secure e-fax: {pages} pages waiting",
        from_header="Riverbend eFax <fax@riverbendmg-efax.example>",
        reply_to="fax@riverbendmg-efax.example",
        body=(
            "Hello,\n\n"
            "You have a secure e-fax of {pages} pages from a referring clinician, "
            "tracking {claim}, received {date}. The packet expires tonight.\n\n"
            "Download it immediately: https://efax.riverbendmg-efax.example/inbox/{claim}\n"
            "You will need to verify your identity and sign in. Failure to respond "
            "will delete the referral.\n\n"
            "Riverbend secure fax"
        ),
    )
    add(
        "referral",
        1,
        1,
        subject="Encrypted referral for {patient}",
        from_header="Westbridge Referrals <referrals.desk@gmail.com>",
        reply_to="referrals.desk@gmail.com",
        attachments=[{"filename": "Referral_{claim}.docm", "content_type": "application/vnd.ms-word.document.macroEnabled.12"}],
        body=(
            "Hello Northwind,\n\n"
            "The referral for {patient} would not go through the fax line. It is attached. "
            "Enable macros to decrypt the {pages} pages. Please open it right away so "
            "the appointment on {date} is not lost.\n\n"
            "Westbridge referrals desk"
        ),
    )
    add(
        "referral",
        1,
        2,
        subject="Patient portal copy of referral {claim}",
        from_header="Riverbend Medical Group <records@riverbendmg.example>",
        reply_to="records@yahoo.com",
        links=[
            {
                "href": "https://riverbendmg.secure-docs.example/r/{claim}",
                "text": "https://referrals.riverbendmg.example/r/{claim}",
            }
        ],
        body=(
            "Hello {patient},\n\n"
            "Your referral packet is ready. Open the records link and confirm your account "
            "so the specialist can see it:\n"
            "https://referrals.riverbendmg.example/r/{claim}\n\n"
            "Do this within 4 hours. The account will be locked after that.\n\n"
            "Riverbend medical records"
        ),
    )
    add(
        "referral",
        1,
        3,
        subject="Fax failed — use this password",
        from_header="Northwind eFax Gateway <fax@northwindc1inic.example>",
        reply_to="fax@northwindc1inic.example",
        body=(
            "Hello,\n\n"
            "An inbound fax for MRN {mrn} failed. Retrieve the {pages} pages with password "
            "and one-time code entry here, immediately:\n"
            "https://fax.northwindc1inic.example/inbox/{claim}\n\n"
            "If you do not sign in, the images will be deleted tonight.\n\n"
            "Northwind fax gateway"
        ),
    )
    add(
        "referral",
        1,
        4,
        subject="Referral images for {patient}",
        from_header="Westbridge Specialty <referrals@westbridgemed.example>",
        reply_to="images@proton.me",
        attachments=[{"filename": "referral_{claim}.iso", "content_type": "application/octet-stream"}],
        body=(
            "Hello,\n\n"
            "The imaging disc for {patient}, MRN {mrn}, is attached as a disk image. "
            "Open it before the consult on {date}. The password is the patient's date of birth.\n\n"
            "Westbridge film library"
        ),
    )
    return rows


TEMPLATES = _templates()


def _rng(template_id: str, variant: int) -> random.Random:
    digest = hashlib.sha256(f"{template_id}:{variant}".encode()).hexdigest()
    # Fills fictional names and claim numbers. Not used for secrets or tokens.
    return random.Random(int(digest[:16], 16))  # nosec B311


def _slots(rng: random.Random) -> dict[str, str]:
    patient_first = rng.choice(FIRST)
    patient_last = rng.choice(LAST)
    staff_first = rng.choice(FIRST)
    staff_last = rng.choice(LAST)
    if (staff_first, staff_last) == (patient_first, patient_last):
        staff_last = "Adler"
    claim_n = rng.randint(100000, 999999)
    mrn_n = rng.randint(100000, 999999)
    invoice_n = rng.randint(1000, 9999)
    return {
        "patient": f"{patient_first} {patient_last}",
        "staff": f"{staff_first} {staff_last}",
        "staff_addr": f"{staff_first}.{staff_last}@northwindclinic.example".lower(),
        "staff_lab": f"{staff_first}.{staff_last}@cedarlabpartners.example".lower(),
        "claim": f"CLM-{claim_n}",
        "mrn": f"MRN-{mrn_n}",
        "invoice": f"INV-{invoice_n}",
        "amount": rng.choice(AMOUNTS),
        "date": rng.choice(DATES),
        "phone": f"555-01{rng.randint(0, 99):02d}",
        "pages": str(rng.randint(2, 9)),
    }


def _format(value: str, slots: dict[str, str]) -> str:
    return value.format(**slots)


def iter_records():
    for spec in TEMPLATES:
        kind = "phish" if spec["label"] == 1 else "legit"
        template_id = f"{spec['theme']}-{kind}-{spec['index']:02d}"
        for variant in range(N_VARIANTS):
            slots = _slots(_rng(template_id, variant))
            attachments = [
                {
                    "filename": _format(item["filename"], slots),
                    "content_type": item["content_type"],
                }
                for item in spec.get("attachments") or []
            ]
            explicit_links = [
                {"href": _format(item["href"], slots), "text": _format(item["text"], slots)}
                for item in spec.get("links") or []
            ]
            record = {
                "id": f"syn-{template_id}-{variant:02d}",
                "split": SPLIT_BY_INDEX[spec["index"]],
                "label": spec["label"],
                "source": "synthetic",
                "category": "healthcare_phish" if spec["label"] == 1 else "healthcare_legit",
                "theme": spec["theme"],
                "template_id": template_id,
                "demo": bool(spec["demo"] and variant == 0),
                "subject": _format(spec["subject"], slots),
                "from": _format(spec["from_header"], slots),
                "reply_to": _format(spec["reply_to"], slots),
                "body": _format(spec["body"], slots),
                "attachments": attachments,
                "license": "MIT",
                "synthetic": True,
            }
            if explicit_links:
                record["links"] = explicit_links
            record["text"] = render_for_model(parsed_from_record(record))
            yield record


def all_records() -> list[dict]:
    return list(iter_records())


def write_jsonl(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = all_records()
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return len(records)


def write_examples(directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for record in all_records():
        if not record.get("demo"):
            continue
        email = parsed_from_record(record)
        name = "phishing_lure.eml" if record["label"] == 1 else "legitimate_notice.eml"
        target = directory / name
        target.write_bytes(to_eml_bytes(email))
        written.append(target)
    return written


def main() -> None:
    from phishguard.paths import examples_dir, synthetic_path

    count = write_jsonl(synthetic_path())
    paths = write_examples(examples_dir())
    print(f"Wrote {count} synthetic messages to {synthetic_path()}")
    for path in paths:
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()

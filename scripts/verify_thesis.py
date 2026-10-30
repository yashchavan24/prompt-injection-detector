import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import pymupdf

doc = pymupdf.open("docs/thesis/Prompt_Injection_Detector_Project_Report.pdf")
print("pages:", doc.page_count)
# footer label = last line on page; print first heading words + footer
for i, page in enumerate(doc):
    text = page.get_text().strip().splitlines()
    first = " | ".join(t.strip() for t in text[:2])
    footer = text[-1].strip() if text else ""
    print(f"p{i+1:02d} footer='{footer}' :: {first[:80]}")

# cover must be navy with gold text present
cover = doc[0]
pix = cover.get_pixmap(clip=pymupdf.Rect(5, 5, 20, 20))
print("cover corner rgb:", pix.pixel(5, 5))
print("gold on cover:", cover.search_for("YASH CHAVAN") is not None)
# screenshots pages should contain images
for i in range(10, 30):
    imgs = doc[i].get_images()
    if imgs:
        print(f"p{i+1}: {len(imgs)} image(s)")
doc.close()

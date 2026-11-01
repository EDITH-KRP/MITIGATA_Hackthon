import pptx
from pptx.oxml import parse_xml
from pptx.oxml.ns import nsdecls

prs = pptx.Presentation()
slide = prs.slides.add_slide(prs.slide_layouts[6])

# Transition: smooth fade / push
transition_xml = parse_xml(f'<p:transition {nsdecls("p")} spd="med" advClick="1"><p:fade/></p:transition>')
slide._element.append(transition_xml)
prs.save('test_anim.pptx')
print("Transition saved successfully!")


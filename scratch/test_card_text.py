import pptx
from pptx.util import Inches, Pt
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

prs = pptx.Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
slide = prs.slides.add_slide(prs.slide_layouts[6])

card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1), Inches(1), Inches(5), Inches(4))
card.fill.solid()
card.fill.fore_color.rgb = RGBColor(18, 25, 42)
card.line.color.rgb = RGBColor(30, 41, 65)
card.line.width = Pt(1.5)

tf = card.text_frame
tf.word_wrap = True
tf.vertical_anchor = MSO_ANCHOR.TOP
tf.margin_left = Inches(0.3)
tf.margin_top = Inches(0.3)
tf.margin_right = Inches(0.3)
tf.margin_bottom = Inches(0.3)

p = tf.paragraphs[0]
p.text = "CARD HEADER"
p.font.name = "Segoe UI"
p.font.size = Pt(14)
p.font.bold = True
p.font.color.rgb = RGBColor(56, 189, 248)
p.space_after = Pt(10)

p2 = tf.add_paragraph()
p2.text = "This is body text directly inside the shape text_frame."
p2.font.name = "Segoe UI"
p2.font.size = Pt(11)
p2.font.color.rgb = RGBColor(248, 250, 252)

prs.save("test_card_text.pptx")
print("Saved card text test!")


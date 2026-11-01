import pptx
from pptx.oxml import parse_xml
from pptx.oxml.ns import nsdecls
from pptx.util import Inches, Pt
from pptx.enum.shapes import MSO_SHAPE

prs = pptx.Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
slide = prs.slides.add_slide(prs.slide_layouts[6])

# Add 2 shapes
s1 = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1), Inches(1), Inches(4), Inches(2))
s2 = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6), Inches(1), Inches(4), Inches(2))

sp_id1 = s1.shape_id
sp_id2 = s2.shape_id
print(f"Shape IDs: {sp_id1}, {sp_id2}")

# Add transition
trans = parse_xml(f'<p:transition {nsdecls("p")} spd="med" advClick="1"><p:fade/></p:transition>')
slide._element.append(trans)

# Helper function to generate timing XML for a list of shape IDs
def build_timing_xml(shape_ids):
    child_nodes = ""
    current_id = 3
    for sp_id in shape_ids:
        c1 = current_id
        c2 = current_id + 1
        c3 = current_id + 2
        c4 = current_id + 3
        current_id += 4
        child_nodes += f"""
        <p:par>
          <p:cTn id="{c1}" fill="hold">
            <p:stCondLst>
              <p:cond delay="0"/>
            </p:stCondLst>
            <p:childTnLst>
              <p:par>
                <p:cTn id="{c2}" fill="hold">
                  <p:stCondLst>
                    <p:cond delay="0"/>
                  </p:stCondLst>
                  <p:childTnLst>
                    <p:set>
                      <p:cBhvr>
                        <p:cTn id="{c3}" dur="1" fill="hold"/>
                        <p:tgtEl>
                          <p:spTgt spid="{sp_id}"/>
                        </p:tgtEl>
                        <p:attrNameLst>
                          <p:attrName>style.visibility</p:attrName>
                        </p:attrNameLst>
                      </p:cBhvr>
                      <p:to>
                        <p:strVal val="visible"/>
                      </p:to>
                    </p:set>
                    <p:animEffect transition="in" filter="fade">
                      <p:cBhvr>
                        <p:cTn id="{c4}" dur="500"/>
                        <p:tgtEl>
                          <p:spTgt spid="{sp_id}"/>
                        </p:tgtEl>
                      </p:cBhvr>
                    </p:animEffect>
                  </p:childTnLst>
                </p:cTn>
              </p:par>
            </p:childTnLst>
          </p:cTn>
        </p:par>
        """

    timing_xml_str = f"""
    <p:timing {nsdecls("p")}>
      <p:tnLst>
        <p:par>
          <p:cTn id="1" dur="indefinite" restart="never" nodeType="tmRoot">
            <p:childTnLst>
              <p:seq concurrent="1" nextAc="seek">
                <p:cTn id="2" dur="indefinite" nodeType="mainSeq">
                  <p:childTnLst>
                    {child_nodes}
                  </p:childTnLst>
                </p:cTn>
                <p:prevCondLst>
                  <p:cond evt="onPrev" delay="0">
                    <p:tgtEl>
                      <p:sldTgt/>
                    </p:tgtEl>
                  </p:cond>
                </p:prevCondLst>
                <p:nextCondLst>
                  <p:cond evt="onNext" delay="0">
                    <p:tgtEl>
                      <p:sldTgt/>
                    </p:tgtEl>
                  </p:cond>
                </p:nextCondLst>
              </p:seq>
            </p:childTnLst>
          </p:cTn>
        </p:par>
      </p:tnLst>
    </p:timing>
    """
    return parse_xml(timing_xml_str)

timing_elem = build_timing_xml([sp_id1, sp_id2])
slide._element.append(timing_elem)

prs.save("test_timing.pptx")

# Verify reopening
prs2 = pptx.Presentation("test_timing.pptx")
print("Reopened successfully! Slides:", len(prs2.slides))


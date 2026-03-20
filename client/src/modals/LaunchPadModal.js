import { useState, useEffect, useCallback } from 'react';
import { Modal, Button, Carousel, Form } from 'react-bootstrap';
import { FaTicketAlt, FaChevronLeft, FaChevronRight, FaCalendarAlt, FaClock, FaUsers, FaVideo, FaSearchPlus, FaTimes } from 'react-icons/fa';

const SLIDES = [
  {
    image: '/images/bblp/1.png',
    alt: 'Bug Bounty Launch Pad - Overview',
  },
  {
    image: '/images/bblp/2.png',
    alt: 'Day 1 - Programs & Tools, Recon Methodology',
  },
  {
    image: '/images/bblp/3.png',
    alt: 'Day 1 - Live Recon Session, Automated Testing Strategies',
  },
  {
    image: '/images/bblp/4.png',
    alt: 'Day 2 - Manual Testing Strategies',
  },
  {
    image: '/images/bblp/5.png',
    alt: 'Day 2 - Continued Learning & Next Steps',
  },
];

const SCHEDULE = [
  {
    day: 'Day 1 - May 16th',
    items: [
      { time: '9 AM CST', label: 'Introduction, Programs & Tools' },
      { time: '10 AM CST', label: 'Recon Methodology' },
      { time: '12 PM CST', label: 'Lunch Break' },
      { time: '1 PM CST', label: 'Live Recon Session' },
      { time: '4 PM CST', label: 'Open Q&A' },
    ],
  },
  {
    day: 'Day 2 - May 17th',
    items: [
      { time: '9 AM CST', label: 'Automated Testing Strategies' },
      { time: '10 AM CST', label: 'Manual Testing Strategies' },
      { time: '12 PM CST', label: 'Lunch Break' },
      { time: '1 PM CST', label: 'Live Hunting Session' },
      { time: '4 PM CST', label: 'Continued Learning & Next Steps' },
      { time: '5 PM CST', label: 'Open Q&A' },
    ],
  },
];

const TESTIMONIALS = [
  {
    text: "As a Partner Hunter within our bug bounty community, I'm always looking for ways to refine our collective methodology. I joined a live session with rs0n and about 50+ other practitioners for a 9-hour deep dive into the craft. Even with an Offsec background, there is immense value in seeing how other top-tier hunters approach structured recon, manual hunting, and automation. The session was incredibly interactive, and it was great to see so many people actively building and breaking.",
    source: 'Partner Hunter, February 2026',
  },
  {
    text: "I just wrapped up a 9-hour cybersecurity marathon workshop. We went deep into recon strategy, automation workflows that actually scale, manual vulnerability discovery techniques, and SaaS attack surface analysis. No fluff. No recycled basics. Just real-world bug hunting insights and practical execution you can actually apply. Some sessions give you information. Some sessions change the way you think. This one definitely did the second.",
    source: 'Workshop Attendee, February 2026',
  },
  {
    text: "9 hours with rs0n that completely transformed my approach to bug hunting and built a rock-solid mental methodology. 5 intensive sessions that rewired how I think about security. The Manual Hunting Strategies session was the heaviest of all — it bridged recon to hands-on testing with AI/LLM injection techniques. Absolute game-changer. Thank you for the knowledge, the patience, and the roadmap. This changed how I'll hunt forever.",
    source: 'Workshop Attendee, February 2026',
  },
  {
    text: "I would really like to thank rs0n for this amazing workshop. There was a lot of valuable information, and it answered many of the questions I had in my head. It also gave me a clear roadmap to becoming a full-time Bug Bounty Hunter or working in Application Security or Penetration Testing. This workshop truly changed my perspective because it gave me the direction I needed to continue my career and keep learning throughout my journey.",
    source: 'Workshop Attendee, February 2026',
  },
  {
    text: "Personally, I found it extremely helpful. I'm gonna rewatch it once the recording comes out. One of the most information-packed experiences I've been a part of. Would refer. Thank you again!",
    source: 'Discord Community Member',
  },
  {
    text: "Really really there is so much information and answers to questions I really needed to know. But this session gave that to me. I really appreciate it and thank you for your time.",
    source: 'Discord Community Member',
  },
  {
    text: "Being able to stack all of this information in this short amount of time is crazy.",
    source: 'Discord Community Member',
  },
  {
    text: "Thanks again on the workshop, it was amazing!",
    source: 'Discord Community Member',
  },
  {
    text: "Thank you for the recordings, notes, and workshop. It was too good.",
    source: 'Discord Community Member',
  },
  {
    text: "I wasn't able to join live (life is crazy right now) so the recordings are a blessing for me.",
    source: 'Discord Community Member',
  },
];

function LaunchPadModal({ show, handleClose }) {
  const [activeIndex, setActiveIndex] = useState(0);
  const [view, setView] = useState('carousel');
  const [dontShowAgain, setDontShowAgain] = useState(false);
  const [expandedImage, setExpandedImage] = useState(null);

  const handleSelect = (selectedIndex) => {
    setActiveIndex(selectedIndex);
  };

  const handleGetTickets = () => {
    window.open('https://ars0nsecurity.com/products/bug-bounty-launch-pad-may-2026', '_blank');
  };

  const handleDismiss = () => {
    if (dontShowAgain) {
      localStorage.setItem('bblp_modal_dismissed', 'true');
    }
    handleClose();
  };

  const handleExpandedNav = useCallback((direction) => {
    if (expandedImage === null) return;
    const currentIdx = SLIDES.findIndex(s => s.image === expandedImage);
    if (direction === 'next') {
      const nextIdx = (currentIdx + 1) % SLIDES.length;
      setExpandedImage(SLIDES[nextIdx].image);
      setActiveIndex(nextIdx);
    } else {
      const prevIdx = (currentIdx - 1 + SLIDES.length) % SLIDES.length;
      setExpandedImage(SLIDES[prevIdx].image);
      setActiveIndex(prevIdx);
    }
  }, [expandedImage]);

  useEffect(() => {
    if (expandedImage === null) return;
    const handler = (e) => {
      if (e.key === 'Escape') setExpandedImage(null);
      if (e.key === 'ArrowRight') handleExpandedNav('next');
      if (e.key === 'ArrowLeft') handleExpandedNav('prev');
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [expandedImage, handleExpandedNav]);

  return (
    <Modal
      show={show}
      onHide={handleDismiss}
      animation={true}
      size="lg"
      centered
      data-bs-theme="dark"
    >
      <Modal.Header className="border-0 pb-0" style={{ background: '#1a1a1a' }}>
        <div className="w-100 text-center">
          <div className="d-flex align-items-center justify-content-center gap-2 mb-2">
            <img
              src="/images/logo.avif"
              alt="Ars0n Security"
              style={{ width: '40px', height: '40px' }}
            />
            <span className="text-white-50" style={{ fontSize: '0.75rem', letterSpacing: '2px', textTransform: 'uppercase' }}>
              Ars0n Security Presents
            </span>
          </div>
          <h3 className="mb-1 text-danger" style={{ fontWeight: 800, letterSpacing: '1px' }}>
            Bug Bounty Launch Pad!
          </h3>
          <p className="text-white mb-2" style={{ fontSize: '0.95rem', opacity: 0.9 }}>
            A 2-Day Hands-On Live Virtual Workshop Hosted by rs0n
          </p>
          <div className="d-flex justify-content-center gap-4 mb-2" style={{ fontSize: '0.8rem' }}>
            <span className="text-white-50">
              <FaCalendarAlt className="me-1 text-danger" />
              May 16-17, 2026
            </span>
            <span className="text-white-50">
              <FaClock className="me-1 text-danger" />
              9 AM - 6 PM CST
            </span>
            <span className="text-white-50">
              <FaUsers className="me-1 text-danger" />
              Limited to 50 Seats
            </span>
          </div>
        </div>
      </Modal.Header>

      <Modal.Body className="px-3 py-3" style={{ background: '#1a1a1a' }}>
        <div className="d-flex justify-content-center gap-2 mb-3">
          <Button
            variant={view === 'carousel' ? 'danger' : 'outline-danger'}
            size="sm"
            onClick={() => setView('carousel')}
            style={{ fontSize: '0.8rem', borderRadius: '20px', padding: '4px 16px' }}
          >
            Curriculum
          </Button>
          <Button
            variant={view === 'schedule' ? 'danger' : 'outline-danger'}
            size="sm"
            onClick={() => setView('schedule')}
            style={{ fontSize: '0.8rem', borderRadius: '20px', padding: '4px 16px' }}
          >
            Schedule
          </Button>
          <Button
            variant={view === 'testimonials' ? 'danger' : 'outline-danger'}
            size="sm"
            onClick={() => setView('testimonials')}
            style={{ fontSize: '0.8rem', borderRadius: '20px', padding: '4px 16px' }}
          >
            Testimonials
          </Button>
        </div>

        {view === 'carousel' && (
          <div style={{ position: 'relative' }}>
            <Carousel
              activeIndex={activeIndex}
              onSelect={handleSelect}
              interval={null}
              indicators={true}
              prevIcon={
                <span style={{
                  background: 'rgba(220, 53, 69, 0.85)',
                  borderRadius: '50%',
                  width: '36px',
                  height: '36px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  <FaChevronLeft size={14} />
                </span>
              }
              nextIcon={
                <span style={{
                  background: 'rgba(220, 53, 69, 0.85)',
                  borderRadius: '50%',
                  width: '36px',
                  height: '36px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  <FaChevronRight size={14} />
                </span>
              }
            >
              {SLIDES.map((slide, idx) => (
                <Carousel.Item key={idx}>
                  <div
                    onClick={() => setExpandedImage(slide.image)}
                    style={{
                      display: 'flex',
                      justifyContent: 'center',
                      alignItems: 'center',
                      background: '#141414',
                      borderRadius: '8px',
                      overflow: 'hidden',
                      minHeight: '420px',
                      cursor: 'zoom-in',
                      position: 'relative',
                    }}
                  >
                    <img
                      src={slide.image}
                      alt={slide.alt}
                      style={{
                        maxWidth: '100%',
                        maxHeight: '420px',
                        objectFit: 'contain',
                      }}
                    />
                    <div style={{
                      position: 'absolute',
                      bottom: '10px',
                      right: '10px',
                      background: 'rgba(220, 53, 69, 0.85)',
                      borderRadius: '50%',
                      width: '32px',
                      height: '32px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}>
                      <FaSearchPlus size={14} color="#fff" />
                    </div>
                  </div>
                </Carousel.Item>
              ))}
            </Carousel>
            <div className="text-center mt-2">
              <span className="text-white-50" style={{ fontSize: '0.75rem' }}>
                {activeIndex + 1} / {SLIDES.length} — Click image to expand, use arrows to browse
              </span>
            </div>
          </div>
        )}

        {expandedImage && (
          <div
            onClick={() => setExpandedImage(null)}
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'rgba(0, 0, 0, 0.92)',
              zIndex: 9999,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'zoom-out',
            }}
          >
            <button
              onClick={(e) => { e.stopPropagation(); setExpandedImage(null); }}
              style={{
                position: 'absolute',
                top: '20px',
                right: '20px',
                background: 'rgba(220, 53, 69, 0.85)',
                border: 'none',
                borderRadius: '50%',
                width: '40px',
                height: '40px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                zIndex: 10000,
              }}
            >
              <FaTimes size={18} color="#fff" />
            </button>

            <button
              onClick={(e) => { e.stopPropagation(); handleExpandedNav('prev'); }}
              style={{
                position: 'absolute',
                left: '20px',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'rgba(220, 53, 69, 0.85)',
                border: 'none',
                borderRadius: '50%',
                width: '44px',
                height: '44px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                zIndex: 10000,
              }}
            >
              <FaChevronLeft size={18} color="#fff" />
            </button>

            <img
              src={expandedImage}
              alt="Expanded curriculum"
              onClick={(e) => e.stopPropagation()}
              style={{
                maxWidth: '90vw',
                maxHeight: '90vh',
                objectFit: 'contain',
                cursor: 'default',
                borderRadius: '8px',
              }}
            />

            <button
              onClick={(e) => { e.stopPropagation(); handleExpandedNav('next'); }}
              style={{
                position: 'absolute',
                right: '20px',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'rgba(220, 53, 69, 0.85)',
                border: 'none',
                borderRadius: '50%',
                width: '44px',
                height: '44px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                zIndex: 10000,
              }}
            >
              <FaChevronRight size={18} color="#fff" />
            </button>

            <div style={{
              position: 'absolute',
              bottom: '20px',
              left: '50%',
              transform: 'translateX(-50%)',
            }}>
              <span className="text-white-50" style={{ fontSize: '0.8rem' }}>
                {SLIDES.findIndex(s => s.image === expandedImage) + 1} / {SLIDES.length} — Arrow keys to navigate, Esc to close
              </span>
            </div>
          </div>
        )}

        {view === 'schedule' && (
          <div style={{
            background: '#141414',
            borderRadius: '8px',
            padding: '20px',
            maxHeight: '460px',
            overflowY: 'auto',
          }}>
            {SCHEDULE.map((day, idx) => (
              <div key={idx} className={idx > 0 ? 'mt-3' : ''}>
                <h6 className="text-danger" style={{ fontWeight: 700, marginBottom: '12px' }}>
                  <FaCalendarAlt className="me-2" />
                  {day.day}
                </h6>
                {day.items.map((item, i) => (
                  <div
                    key={i}
                    className="d-flex align-items-center mb-2"
                    style={{
                      background: item.label === 'Lunch Break' ? 'rgba(255,255,255,0.03)' : 'rgba(255, 0, 0, 0.06)',
                      borderRadius: '6px',
                      padding: '8px 12px',
                      borderLeft: item.label === 'Lunch Break' ? '3px solid rgba(255,255,255,0.15)' : '3px solid #dc3545',
                    }}
                  >
                    <span className="text-danger" style={{
                      fontWeight: 600,
                      fontSize: '0.8rem',
                      minWidth: '100px',
                      fontFamily: 'monospace',
                    }}>
                      {item.time}
                    </span>
                    <span className="text-white" style={{ fontSize: '0.85rem' }}>
                      {item.label}
                    </span>
                  </div>
                ))}
              </div>
            ))}
            <div className="mt-3 p-3" style={{
              background: 'rgba(255, 0, 0, 0.06)',
              borderRadius: '8px',
              border: '1px solid rgba(255, 0, 0, 0.15)',
            }}>
              <p className="text-white-50 mb-2" style={{ fontSize: '0.8rem' }}>
                Each day features morning lectures followed by afternoon hands-on sessions where
                you'll apply what you've learned in real-time recon and hunting exercises,
                wrapping up with open Q&A.
              </p>
              <p className="text-white-50 mb-0" style={{ fontSize: '0.8rem' }}>
                <FaVideo className="me-1 text-danger" />
                Recordings of all sessions and slides will be provided after the workshop is complete.
              </p>
            </div>
          </div>
        )}

        {view === 'testimonials' && (
          <div style={{
            background: '#141414',
            borderRadius: '8px',
            padding: '20px',
            maxHeight: '460px',
            overflowY: 'auto',
          }}>
            {TESTIMONIALS.map((t, idx) => (
              <div key={idx} className={`p-3 ${idx < TESTIMONIALS.length - 1 ? 'mb-3' : ''}`} style={{
                background: 'rgba(255, 0, 0, 0.04)',
                borderRadius: '8px',
                borderLeft: '3px solid #dc3545',
              }}>
                <p className="text-white mb-2" style={{ fontSize: '0.85rem', fontStyle: 'italic', lineHeight: 1.6 }}>
                  "{t.text}"
                </p>
                <span className="text-white-50" style={{ fontSize: '0.75rem' }}>
                  — {t.source}
                </span>
              </div>
            ))}

            <div className="mt-3 p-3" style={{
              background: 'rgba(255, 0, 0, 0.06)',
              borderRadius: '8px',
              border: '1px solid rgba(255, 0, 0, 0.15)',
            }}>
              <p className="text-white-50 mb-0" style={{ fontSize: '0.8rem' }}>
                The first Bug Bounty Launch Pad sold out with 50 attendees. Expect generous
                ticket giveaways leading up to May — join the Ars0n Security Discord to stay
                in the loop!
              </p>
            </div>
          </div>
        )}
      </Modal.Body>

      <Modal.Footer className="border-0 pt-0 flex-column" style={{ background: '#1a1a1a' }}>
        <div className="d-flex justify-content-between align-items-center w-100 mb-2">
          <Button
            variant="outline-secondary"
            size="sm"
            onClick={handleDismiss}
            style={{ borderRadius: '20px', padding: '6px 20px', fontSize: '0.85rem' }}
          >
            Maybe Later
          </Button>
          <Button
            variant="danger"
            size="sm"
            onClick={handleGetTickets}
            style={{
              borderRadius: '20px',
              padding: '6px 24px',
              fontSize: '0.85rem',
              fontWeight: 600,
              border: 'none',
              boxShadow: '0 4px 15px rgba(255, 0, 0, 0.3)',
            }}
          >
            <FaTicketAlt className="me-2" />
            Get Your Tickets!
          </Button>
        </div>
        <Form.Check
          type="checkbox"
          id="bblp-dont-show"
          label="Don't show this again"
          checked={dontShowAgain}
          onChange={(e) => setDontShowAgain(e.target.checked)}
          className="text-white-50"
          style={{ fontSize: '0.78rem' }}
        />
      </Modal.Footer>
    </Modal>
  );
}

export default LaunchPadModal;

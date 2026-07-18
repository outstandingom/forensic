import React, { useState } from 'react';
import './BecomePartner.css';

interface UserProfile {
  id: string;
  isPartner: boolean;
  partnerCode: string | null;
  walletBalance: number;
}

export const BecomePartner: React.FC = () => {
  // In a real application, you would fetch this from your backend/state management
  const [profile, setProfile] = useState<UserProfile>({
    id: 'user-123',
    isPartner: false,
    partnerCode: null,
    walletBalance: 0,
  });

  const [isLoading, setIsLoading] = useState(false);

  const handleBecomePartner = async () => {
    setIsLoading(true);
    
    // Simulate API call to enroll as a partner and generate a code
    setTimeout(() => {
      setProfile((prev) => ({
        ...prev,
        isPartner: true,
        // In reality, this would be returned from your backend
        partnerCode: 'PARTNER-' + Math.random().toString(36).substring(2, 8).toUpperCase(),
        walletBalance: 0,
      }));
      setIsLoading(false);
    }, 1200);
  };

  const copyToClipboard = () => {
    if (profile.partnerCode) {
      navigator.clipboard.writeText(profile.partnerCode);
      alert('Partner code copied to clipboard!');
    }
  };

  return (
    <div className="partner-card">
      <div className="partner-header">
        <h2>Partner Program</h2>
        {profile.isPartner && <span className="badge">Active Partner</span>}
      </div>

      {!profile.isPartner ? (
        <div className="partner-content unrolled">
          <p>
            Turn your network into income! Become an official partner today. 
            Share your unique code to give your friends <strong>20% off</strong> our 
            Website-to-App Converter, and you'll earn <strong>30%</strong> of the sale amount directly to your wallet!
          </p>
          <button 
            className={`partner-btn ${isLoading ? 'loading' : ''}`} 
            onClick={handleBecomePartner}
            disabled={isLoading}
          >
            {isLoading ? 'Enrolling...' : 'Become a Partner Now'}
          </button>
        </div>
      ) : (
        <div className="partner-content enrolled">
          <div className="wallet-section">
            <div className="wallet-balance">
              <span className="label">Wallet Balance</span>
              <span className="amount">🪙 {profile.walletBalance.toFixed(2)} Coins</span>
            </div>
          </div>
          
          <div className="code-section">
            <p className="code-description">
              Share your partner code below! Users get 20% off the <strong>Website-to-App Converter</strong>, 
              and you receive 30% of the sale as coins.
            </p>
            <div className="code-box" onClick={copyToClipboard} title="Click to copy">
              <span className="code">{profile.partnerCode}</span>
              <button className="copy-btn">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M8 4V16C8 17.1046 8.89543 18 10 18H20C21.1046 18 22 17.1046 22 16V4C22 2.89543 21.1046 2 20 2H10C8.89543 2 8 2.89543 8 4Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M16 18V20C16 21.1046 15.1046 22 14 22H4C2.89543 22 2 21.1046 2 20V8C2 6.89543 2.89543 6 4 6H6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

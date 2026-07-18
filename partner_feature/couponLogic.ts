/**
 * This file contains the logic for applying a partner's coupon code to a purchase
 * and crediting the partner's wallet.
 * 
 * It can be adapted to work within a Next.js API Route, Express server, or similar Node environment.
 */

// Example types (replace with your ORM / DB types)
interface PurchaseRequest {
  buyerId: string;
  productName: string; // Should be "Website-to-App Converter" for this specific promotion
  originalPrice: number;
  partnerCode?: string;
}

interface ProcessPurchaseResult {
  success: boolean;
  finalPrice: number;
  discountApplied: number;
  message: string;
}

// Mock database functions for demonstration
const db = {
  findPartnerByCode: async (code: string) => {
    // In a real app: SELECT * FROM partner_profiles WHERE partner_code = code
    return { userId: 'partner-123', partnerCode: code, isPartner: true }; // mock
  },
  updatePartnerWallet: async (partnerCode: string, amountToAdd: number) => {
    // In a real app: UPDATE partner_profiles SET wallet_balance = wallet_balance + amountToAdd WHERE partner_code = partnerCode
    console.log(`Added ${amountToAdd} coins to partner ${partnerCode}`);
  },
  recordPurchase: async (purchaseData: any) => {
    // In a real app: INSERT INTO partner_purchases (...)
    console.log(`Recorded purchase:`, purchaseData);
  }
};

/**
 * Process a purchase and apply the 20% discount / 30% partner reward if a valid code is used.
 */
export async function processPurchase(req: PurchaseRequest): Promise<ProcessPurchaseResult> {
  const { buyerId, productName, originalPrice, partnerCode } = req;
  
  let finalPrice = originalPrice;
  let discountApplied = 0;
  let partnerRewardCoins = 0;
  let appliedCode = null;

  // The promotion is specifically for the Website-to-App Converter
  const isEligibleProduct = productName === "Website-to-App Converter";

  if (partnerCode && isEligibleProduct) {
    try {
      const partner = await db.findPartnerByCode(partnerCode);
      
      if (partner && partner.isPartner) {
        // Buyer gets 20% discount
        discountApplied = originalPrice * 0.20;
        finalPrice = originalPrice - discountApplied;
        appliedCode = partnerCode;

        // Partner gets 30% of the ORIGINAL amount as coins
        partnerRewardCoins = originalPrice * 0.30;
        
        // Add coins to partner's wallet
        await db.updatePartnerWallet(partnerCode, partnerRewardCoins);
      }
    } catch (error) {
      console.error("Error validating partner code:", error);
      // Fallback to no discount if DB query fails, or handle as needed
    }
  }

  // Record the transaction
  await db.recordPurchase({
    buyer_id: buyerId,
    product_name: productName,
    original_price: originalPrice,
    discount_applied: discountApplied,
    final_price: finalPrice,
    applied_partner_code: appliedCode,
    partner_reward_coins: partnerRewardCoins
  });

  return {
    success: true,
    finalPrice,
    discountApplied,
    message: appliedCode ? `Coupon applied! 20% discount granted.` : `Purchase complete.`
  };
}

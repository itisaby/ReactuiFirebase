import { CSSProperties } from "react";
declare type Orientation = "vertical" | "horizontal";
export declare function getPartsStyle(options: {
    orientation: Orientation;
    trackPercent: number;
    thumbRect: {
        height: number;
        width: number;
    };
    isReversed?: boolean;
}): {
    trackStyle: CSSProperties;
    innerTrackStyle: CSSProperties;
    rootStyle: CSSProperties;
    thumbStyle: CSSProperties;
};
export declare function getIsReversed(options: {
    isReversed?: boolean;
    direction: "ltr" | "rtl";
    orientation?: "horizontal" | "vertical";
}): boolean | undefined;
export {};
//# sourceMappingURL=slider-utils.d.ts.map